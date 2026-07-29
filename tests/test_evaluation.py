from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import ctf_os.evaluation as evaluation_module
from ctf_os import cli
from ctf_os.evaluation import EvaluationError, evaluate_workspace
from ctf_os.models import (
    ArtifactReference,
    ChallengeIdentity,
    ChallengeStatus,
    Experiment,
    ExperimentStatus,
    FlagCandidate,
    ProgressMarker,
    RunReference,
    RunStatus,
    SubmissionReference,
    SubmissionStatus,
)
from ctf_os.store import StateStore, sha256_file
from ctf_os.store.atomic import atomic_write_json


def _later(timestamp: str, seconds: int) -> str:
    normalized = (
        timestamp[:-1] + "+00:00"
        if timestamp.endswith("Z")
        else timestamp
    )
    value = datetime.fromisoformat(normalized).astimezone(timezone.utc)
    return (
        (value + timedelta(seconds=seconds))
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


class EvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.store = StateStore(self.root)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _create_attempt(
        self,
        attempt: int,
        *,
        accepted: bool,
        points: float | None,
        rejected_proof: bool = False,
        proof_result: bool = False,
        budget_seconds: int | None = 60,
    ) -> ChallengeIdentity:
        identity = ChallengeIdentity(
            "contest",
            "rev",
            f"fixture-{attempt}",
        )
        state = self.store.create_challenge(
            identity,
            metadata={
                "evaluation_case_id": "fixture",
                "evaluation_attempt": attempt,
            },
            budget=(
                {"allocated_seconds": budget_seconds}
                if budget_seconds is not None
                else None
            ),
        )
        artifact: ArtifactReference | None = None
        if proof_result:
            relative = Path("proof") / "C-1" / "eval-1" / "result.json"
            path = self.store.challenge_paths(identity).root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "passed": True,
                "candidate": "KCTF{fixture}",
                "policy_mode": "deterministic",
                "successful_attempts": 2,
                "required_attempts": 2,
                "total_attempts": 3,
                "source_manifest_sha256": "a" * 64,
                "failures": ["proof-3: exact candidate was not reproduced"],
                "run_ids": ["proof-1", "proof-2", "proof-3"],
            }
            atomic_write_json(path, payload, mode=0o400)
            artifact = ArtifactReference(
                id="A-proof",
                path=relative.as_posix(),
                sha256=sha256_file(path),
                size=path.stat().st_size,
                created_at=_later(state.created_at, 20),
            )

        def apply(current) -> None:
            current.progress_markers.append(
                ProgressMarker(
                    id=f"PM-{attempt}",
                    statement="first meaningful primitive",
                    elapsed_seconds=5,
                )
            )
            current.runs.extend(
                (
                    RunReference(
                        id=f"model-{attempt}",
                        base_revision=current.revision,
                        status=RunStatus.COMPLETED,
                        role="recon",
                        model="model-id",
                        extra={
                            "usage": {
                                "input_tokens": 10,
                                "cached_input_tokens": 2,
                                "output_tokens": 3,
                                "reasoning_output_tokens": 1,
                            }
                        },
                    ),
                    RunReference(
                        id=f"tool-{attempt}",
                        base_revision=current.revision,
                        status=RunStatus.COMPLETED,
                        role="tool",
                        extra={"wall_seconds": 2.5},
                    ),
                )
            )
            if attempt == 2:
                current.runs.append(
                    RunReference(
                        id="invalid-contract",
                        base_revision=current.revision,
                        status=RunStatus.INVALID,
                        role="falsifier",
                        model="model-id",
                        extra={
                            "contract_errors": ["unexpected output key"]
                        },
                    )
                )
                current.budget.refusals.append(
                    {
                        "run_id": "invalid-contract",
                        "kind": "policy",
                        "message": "synthetic refusal",
                    }
                )
            for index in range(2):
                current.experiments.append(
                    Experiment(
                        id=f"E-{attempt}-{index}",
                        hypothesis_ids=[],
                        command="python3 solve.py",
                        expected_observation="bounded output",
                        keep_if="new evidence appears",
                        drop_if="no evidence appears",
                        timeout_seconds=30,
                        status=ExperimentStatus.FAILED,
                    )
                )
            candidate_status = (
                "ACCEPTED"
                if accepted
                else "REJECTED"
                if rejected_proof
                else "OBSERVED_CANDIDATE"
            )
            current.candidates.append(
                FlagCandidate(
                    id="C-1",
                    value="KCTF{fixture}",
                    status=candidate_status,
                )
            )
            if accepted or rejected_proof:
                status = (
                    SubmissionStatus.ACCEPTED
                    if accepted
                    else SubmissionStatus.REJECTED
                )
                current.submissions.append(
                    SubmissionReference(
                        id=f"SUB-{attempt}",
                        candidate_id="C-1",
                        status=status,
                        submitted_at=_later(state.created_at, 30),
                        proof_passed=proof_result or rejected_proof,
                        points=points,
                    )
                )
            if accepted:
                current.status = ChallengeStatus.SOLVED
            if artifact is not None:
                current.artifacts.append(artifact)

        self.store.update(identity, apply)
        return identity

    def test_aggregates_only_canonical_evidence(self) -> None:
        self._create_attempt(
            1,
            accepted=True,
            points=100,
            proof_result=True,
        )
        self._create_attempt(
            2,
            accepted=False,
            points=None,
            rejected_proof=True,
        )
        self._create_attempt(3, accepted=True, points=50)

        report = evaluate_workspace(self.root)
        metrics = report.metrics

        self.assertTrue(report.complete)
        self.assertEqual(report.evaluated_states, 3)
        self.assertTrue(
            metrics["fixed_budget_comparability"].value["comparable"]
        )
        self.assertEqual(metrics["solve@1"].status, "available")
        self.assertEqual(metrics["solve@1"].value["rate"], 1.0)
        self.assertEqual(metrics["solve@3"].value["rate"], 1.0)
        self.assertEqual(
            metrics["consistency"].value["three_of_three_cases"], 0
        )
        self.assertEqual(
            metrics["clean_reproduction_rate"].value["rate"],
            round(2 / 3, 6),
        )
        self.assertEqual(
            metrics["false_proof_count"].value,
            {"count": 1, "audited_proof_submissions": 2},
        )
        self.assertEqual(
            metrics["time_to_first_primitive"].value["mean_seconds"],
            5.0,
        )
        self.assertEqual(
            metrics["time_to_proof"].value["mean_seconds"], 20.0
        )
        self.assertEqual(
            metrics["repeated_command_count"].value["count"], 3
        )
        self.assertEqual(
            metrics["model_usage"].value["input_tokens"], 30
        )
        self.assertEqual(metrics["model_usage"].status, "partial")
        self.assertEqual(
            metrics["tool_wall_time"].value["total_seconds"], 7.5
        )
        self.assertEqual(metrics["refusal_count"].value["count"], 1)
        self.assertEqual(
            metrics["invalid_contract_count"].value["count"], 1
        )
        self.assertEqual(metrics["manual_points"].value["total"], 150.0)
        self.assertEqual(
            metrics["stall_recovery_rate"].status, "unavailable"
        )
        self.assertIn(
            "not stall episode outcomes",
            metrics["stall_recovery_rate"].reason,
        )

    def test_solve_metrics_are_partial_when_fixed_budgets_differ(self) -> None:
        self._create_attempt(1, accepted=True, points=100, budget_seconds=60)
        self._create_attempt(2, accepted=False, points=None, budget_seconds=61)
        self._create_attempt(3, accepted=True, points=50, budget_seconds=60)

        metrics = evaluate_workspace(self.root).metrics
        comparability = metrics["fixed_budget_comparability"]
        self.assertEqual(comparability.status, "available")
        self.assertFalse(comparability.value["comparable"])
        self.assertEqual(metrics["solve@1"].status, "partial")
        self.assertEqual(metrics["solve@3"].status, "partial")
        self.assertIn("budgets differ", metrics["solve@3"].reason)

    def test_solve_metrics_are_partial_without_canonical_budget(self) -> None:
        self._create_attempt(
            1,
            accepted=True,
            points=100,
            budget_seconds=None,
        )

        metrics = evaluate_workspace(self.root).metrics
        self.assertEqual(
            metrics["fixed_budget_comparability"].status,
            "unavailable",
        )
        self.assertEqual(metrics["solve@1"].status, "partial")
        self.assertIn("fixed wall budget", metrics["solve@1"].reason)

    def test_missing_evidence_is_unavailable_not_zero(self) -> None:
        identity = ChallengeIdentity("contest", "crypto", "empty")
        self.store.create_challenge(identity)

        report = evaluate_workspace(
            self.root,
            contest_id="contest",
            category="crypto",
            challenge_id="empty",
        )
        metrics = report.metrics

        for name in (
            "solve@1",
            "solve@3",
            "clean_reproduction_rate",
            "false_proof_count",
            "time_to_first_primitive",
            "time_to_proof",
            "model_usage",
            "tool_wall_time",
            "stall_recovery_rate",
        ):
            with self.subTest(metric=name):
                self.assertEqual(metrics[name].status, "unavailable")
                self.assertTrue(metrics[name].reason)
        self.assertEqual(metrics["manual_points"].value["total"], 0.0)

    def test_invalid_proof_is_bounded_and_reported(self) -> None:
        identity = ChallengeIdentity("contest", "pwn", "bad-proof")
        state = self.store.create_challenge(identity)
        relative = Path("proof") / "C-1" / "eval-1" / "result.json"
        path = self.store.challenge_paths(identity).root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(path, {"passed": True}, mode=0o400)

        def apply(current) -> None:
            current.candidates.append(
                FlagCandidate(id="C-1", value="KCTF{candidate}")
            )
            current.artifacts.append(
                ArtifactReference(
                    id="A-bad-proof",
                    path=relative.as_posix(),
                    sha256=sha256_file(path),
                    size=path.stat().st_size,
                    created_at=_later(state.created_at, 2),
                )
            )

        self.store.update(identity, apply)

        first = evaluate_workspace(self.root).to_dict()
        second = evaluate_workspace(self.root).to_dict()
        self.assertEqual(first, second)
        clean = first["metrics"]["clean_reproduction_rate"]
        self.assertEqual(clean["status"], "unavailable")
        self.assertIn("invalid", clean["reason"])
        self.assertTrue(first["diagnostics"])
        serialized = json.dumps(first, ensure_ascii=False)
        self.assertLess(len(serialized.encode("utf-8")), 128 * 1024)

    def test_proof_parsing_uses_the_same_verified_descriptor(self) -> None:
        identity = self._create_attempt(
            1,
            accepted=True,
            points=100,
            proof_result=True,
        )
        proof_path = (
            self.store.challenge_paths(identity).root
            / "proof"
            / "C-1"
            / "eval-1"
            / "result.json"
        )
        replacement = {
            "passed": False,
            "candidate": "KCTF{fixture}",
            "policy_mode": "deterministic",
            "successful_attempts": 0,
            "required_attempts": 2,
            "total_attempts": 3,
            "source_manifest_sha256": "a" * 64,
            "failures": ["replacement"],
            "run_ids": ["proof-1", "proof-2", "proof-3"],
        }
        original_open = os.open
        replaced = False

        def replace_after_open(path, flags, *args, **kwargs):
            nonlocal replaced
            descriptor = original_open(path, flags, *args, **kwargs)
            if (
                not replaced
                and path == "result.json"
                and kwargs.get("dir_fd") is not None
            ):
                replaced = True
                atomic_write_json(proof_path, replacement, mode=0o400)
            return descriptor

        with patch.object(
            evaluation_module.os,
            "open",
            side_effect=replace_after_open,
        ):
            report = evaluate_workspace(self.root)

        self.assertTrue(replaced)
        clean = report.metrics["clean_reproduction_rate"]
        self.assertEqual(clean.status, "available")
        self.assertEqual(clean.value["successful_attempts"], 2)
        self.assertEqual(clean.value["total_attempts"], 3)

    def test_selection_limit_is_explicitly_partial(self) -> None:
        for challenge in ("a", "b"):
            self.store.create_challenge(
                ChallengeIdentity("contest", "web", challenge),
                metadata={
                    "evaluation_case_id": challenge,
                    "evaluation_attempt": 1,
                },
            )

        report = evaluate_workspace(self.root, max_states=1)
        self.assertTrue(report.truncated)
        self.assertFalse(report.complete)
        self.assertEqual(report.selected_states, 1)
        self.assertEqual(report.metrics["solve@1"].status, "partial")
        self.assertIn(
            "first 1 canonical states",
            report.metrics["solve@1"].reason,
        )

    def test_scope_requires_parent_components(self) -> None:
        with self.assertRaisesRegex(
            EvaluationError, "category scope requires"
        ):
            evaluate_workspace(self.root, category="rev")

    def test_cli_evaluate_does_not_construct_engine_or_mutate_state(self) -> None:
        identity = ChallengeIdentity("contest", "rev", "cli")
        self.store.create_challenge(identity)
        state_path = self.store.challenge_paths(identity).state
        before = state_path.read_bytes()
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            patch(
                "ctf_os.cli.ChallengeEngine",
                side_effect=AssertionError("engine must not be constructed"),
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = cli.main(
                ["evaluate", "--contest", "contest"],
                root=self.root,
            )

        self.assertEqual(status, 0, stderr.getvalue())
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["evaluated_states"], 1)
        self.assertEqual(state_path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
