from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ctf_os import cli
from ctf_os.benchmark import CTF_OS_SYSTEM, THIN_SCAFFOLD
from ctf_os.config import default_config_text, set_runtime_image_digest
from ctf_os.models import (
    ArtifactReference,
    Budget,
    BudgetMode,
    CandidateStatus,
    ChallengeStatus,
    FlagCandidate,
    RunReference,
    RunStatus,
    SubmissionReference,
    SubmissionStatus,
)
from ctf_os.promotion_bundles import (
    PromotionBundleError,
    capture_promotion_session,
    finalize_promotion_session,
    evaluate_promotion_bundles,
    freeze_promotion_manifest,
    local_execution_fingerprint,
    parse_promotion_manifest,
    prepare_promotion_session,
)
from ctf_os.store import StateStore, sha256_file
from ctf_os.store.atomic import (
    atomic_write_json,
    atomic_write_text,
)


CATEGORIES = ("pwn", "web", "rev", "crypto", "forensics", "misc")


def _later(timestamp: str, seconds: int) -> str:
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return (
        (parsed + timedelta(seconds=seconds))
        .astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _case_layout() -> dict[str, tuple[tuple[str, str], ...]]:
    return {
        "dev": (("dev-pwn", "pwn"),),
        "regression": (("regression-web", "web"),),
        "blind": tuple(
            (f"blind-{category}", category)
            for category in CATEGORIES
        ),
        "live": tuple(
            (f"live-{category}", category)
            for category in CATEGORIES
        ),
    }


def _manifest(
    fingerprint: dict[str, str] | None = None,
) -> dict[str, object]:
    splits: list[dict[str, object]] = []
    for split, cases in _case_layout().items():
        case_records: list[dict[str, object]] = []
        for case_id, category in cases:
            sessions: list[dict[str, object]] = []
            for arm in (THIN_SCAFFOLD, CTF_OS_SYSTEM):
                for attempt in (1, 2, 3):
                    session_id = f"{case_id}-{arm}-{attempt}"
                    sessions.append(
                        {
                            "session_id": session_id,
                            "arm": arm,
                            "attempt": attempt,
                            "contest_id": "bundle-bench",
                            "category": category,
                            "challenge_id": session_id,
                        }
                    )
            case_records.append(
                {
                    "case_id": case_id,
                    "category": category,
                    "input_manifest_sha256": hashlib.sha256(
                        case_id.encode("ascii")
                    ).hexdigest(),
                    "sessions": sessions,
                }
            )
        splits.append(
            {
                "name": split,
                "trajectory_visible": split == "dev",
                "answers_visible": False,
                "prior_engine_runs": 1 if split == "regression" else 0,
                "cases": case_records,
            }
        )
    return {
        "schema_version": 1,
        "benchmark_id": "paired-bundle-fixture",
        "model_id": "gpt-5.6-sol",
        "budget": {
            "wall_seconds": 60,
            "model_call_limit": 8,
            "total_token_limit": 100_000,
        },
        "execution_fingerprint": fingerprint
        or {
            "tool_manifest_sha256": "1" * 64,
            "image_sha256": "2" * 64,
            "model_config_sha256": "3" * 64,
        },
        "splits": splits,
    }


class PromotionBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.store = StateStore(self.root)
        self.manifest_path = self.root / "manifest.json"
        self.frozen_path = self.root / "manifest.frozen.json"
        config_path = self.root / ".ctfos" / "engine.toml"
        atomic_write_text(
            config_path,
            set_runtime_image_digest(
                default_config_text(),
                "sha256:" + "2" * 64,
            ),
            mode=0o600,
        )
        fingerprint = local_execution_fingerprint(self.root)
        self.manifest = _manifest(
            {
                "tool_manifest_sha256": (
                    fingerprint.tool_manifest_sha256
                ),
                "image_sha256": fingerprint.image_sha256,
                "model_config_sha256": (
                    fingerprint.model_config_sha256
                ),
            }
        )
        self.manifest_path.write_text(
            json.dumps(self.manifest, sort_keys=True),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _session_records(self) -> list[tuple[str, str, str, str, int]]:
        parsed = parse_promotion_manifest(self.manifest)
        return [
            (
                session.session_id,
                session.case_id,
                session.split,
                session.arm,
                session.attempt,
            )
            for session in sorted(
                parsed.sessions.values(),
                key=lambda value: value.session_id,
            )
        ]

    def _create_state(
        self,
        session_id: str,
        case_id: str,
        split: str,
        arm: str,
        attempt: int,
    ) -> None:
        parsed = parse_promotion_manifest(self.manifest)
        session = parsed.sessions[session_id]
        metadata = {
            "source_manifest_sha256": (
                session.input_manifest_sha256
            ),
        }
        state = self.store.create_challenge(
            session.identity,
            metadata=metadata,
            budget=Budget(
                allocated_seconds=60,
                spent_seconds=0,
                mode=BudgetMode.BOUNDED,
            ),
            # The generic proof fixture exercises the collector independently
            # from each category's current typed proof contract.  The
            # canonical evaluator upgrades this legacy record before deriving
            # metrics, exactly as it does for retained benchmark history.
            schema_version=1,
            exist_ok=False,
        )
        original_created = datetime.fromisoformat(
            state.created_at.replace("Z", "+00:00")
        )

        state.created_at = (
            (original_created - timedelta(seconds=30))
            .astimezone(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        state.updated_at = state.created_at
        state.validate()
        paths = self.store.challenge_paths(session.identity)
        atomic_write_json(paths.state, state.to_dict(), mode=0o600)
        atomic_write_json(
            paths.previous_state,
            state.to_dict(),
            mode=0o600,
        )
        prepare_promotion_session(
            self.root,
            self.frozen_path,
            session_id=session_id,
        )
        state = self.store.load(session.identity, recover=False)
        seconds = (
            5
            if arm == CTF_OS_SYSTEM and split == "live"
            else 10
        )
        candidate_value = "KCTF{bundle_fixture}"
        artifact: ArtifactReference | None = None
        if arm == CTF_OS_SYSTEM:
            relative = (
                Path("proof") / "C-1" / "eval-1" / "result.json"
            )
            proof_path = (
                self.store.challenge_paths(session.identity).root
                / relative
            )
            proof_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_json(
                proof_path,
                {
                    "passed": True,
                    "candidate": candidate_value,
                    "policy_mode": "deterministic",
                    "successful_attempts": 2,
                    "required_attempts": 2,
                    "total_attempts": 3,
                    "source_manifest_sha256": (
                        session.input_manifest_sha256
                    ),
                    "failures": [
                        "proof-3: exact candidate was not reproduced"
                    ],
                    "run_ids": [
                        f"{session_id}-proof-1",
                        f"{session_id}-proof-2",
                        f"{session_id}-proof-3",
                    ],
                },
                mode=0o400,
            )
            artifact = ArtifactReference(
                id="A-proof",
                path=relative.as_posix(),
                sha256=sha256_file(proof_path),
                size=proof_path.stat().st_size,
                created_at=_later(state.created_at, seconds),
            )

        def mutate(current) -> None:
            current.budget.spent_seconds = 20
            current.runs.append(
                RunReference(
                    id=f"R-{session_id}",
                    base_revision=current.revision,
                    status=RunStatus.COMPLETED,
                    role="explorer",
                    model="gpt-5.6-sol",
                    extra={
                        "usage": {
                            "input_tokens": 100,
                            "cached_input_tokens": 0,
                            "output_tokens": 50,
                            "reasoning_output_tokens": 25,
                        }
                    },
                )
            )
            current.candidates.append(
                FlagCandidate(
                    id="C-1",
                    value=candidate_value,
                    status=CandidateStatus.ACCEPTED,
                )
            )
            current.submissions.append(
                SubmissionReference(
                    id="SUB-1",
                    candidate_id="C-1",
                    status=SubmissionStatus.ACCEPTED,
                    submitted_at=_later(current.created_at, seconds),
                    response="accepted",
                    proof_passed=arm == CTF_OS_SYSTEM,
                    format_ok=True,
                )
            )
            current.status = ChallengeStatus.SOLVED
            if artifact is not None:
                current.artifacts.append(artifact)

        self.store.update(session.identity, mutate)
        finalize_promotion_session(
            self.root,
            self.frozen_path,
            session_id=session_id,
            human_interventions=0,
            secret_or_flag_leaks=0,
        )

    def _freeze(self) -> None:
        freeze_promotion_manifest(
            self.root,
            self.manifest_path,
            self.frozen_path,
        )

    def test_exact_types_leakage_and_missing_attempts_fail_before_freeze(
        self,
    ) -> None:
        base = _manifest()
        mutations: dict[str, dict[str, object]] = {}

        schema_bool = copy.deepcopy(base)
        schema_bool["schema_version"] = True
        mutations["boolean schema version"] = schema_bool

        visibility_integer = copy.deepcopy(base)
        visibility_integer["splits"][2]["answers_visible"] = 0
        mutations["integer visibility"] = visibility_integer

        blind_answer = copy.deepcopy(base)
        blind_answer["splits"][2]["answers_visible"] = True
        mutations["blind answer visibility"] = blind_answer

        blind_trajectory = copy.deepcopy(base)
        blind_trajectory["splits"][2]["trajectory_visible"] = True
        mutations["blind trajectory visibility"] = blind_trajectory

        missing_attempt = copy.deepcopy(base)
        missing_attempt["splits"][0]["cases"][0]["sessions"].pop()
        mutations["missing attempt"] = missing_attempt

        attempt_bool = copy.deepcopy(base)
        attempt_bool["splits"][0]["cases"][0]["sessions"][0][
            "attempt"
        ] = True
        mutations["boolean attempt"] = attempt_bool

        for label, value in mutations.items():
            with self.subTest(label=label):
                with self.assertRaises(PromotionBundleError):
                    parse_promotion_manifest(value)

    def test_cohort_contamination_and_duplicate_run_ids_are_rejected(
        self,
    ) -> None:
        duplicate_identity = _manifest()
        sessions = duplicate_identity["splits"][0]["cases"][0][
            "sessions"
        ]
        sessions[1]["contest_id"] = sessions[0]["contest_id"]
        sessions[1]["category"] = sessions[0]["category"]
        sessions[1]["challenge_id"] = sessions[0]["challenge_id"]
        with self.assertRaisesRegex(
            PromotionBundleError,
            "identity",
        ):
            parse_promotion_manifest(duplicate_identity)

        duplicate_session = _manifest()
        sessions = duplicate_session["splits"][0]["cases"][0][
            "sessions"
        ]
        sessions[1]["session_id"] = sessions[0]["session_id"]
        with self.assertRaisesRegex(
            PromotionBundleError,
            "session_ids",
        ):
            parse_promotion_manifest(duplicate_session)

        duplicate_input = _manifest()
        first = duplicate_input["splits"][0]["cases"][0]
        second = duplicate_input["splits"][1]["cases"][0]
        second["input_manifest_sha256"] = first[
            "input_manifest_sha256"
        ]
        with self.assertRaisesRegex(
            PromotionBundleError,
            "input manifest digests",
        ):
            parse_promotion_manifest(duplicate_input)

    def test_capture_replays_state_and_artifact_hash_tamper_fails_closed(
        self,
    ) -> None:
        self._freeze()
        record = self._session_records()[0]
        self._create_state(*record)
        bundle = self.root / "bundle-one"
        capture = capture_promotion_session(
            self.root,
            self.frozen_path,
            session_id=record[0],
            output_directory=bundle,
        )
        self.assertTrue(capture["collection_complete"])

        proof = next(bundle.rglob("result.json"))
        os.chmod(proof, 0o600)
        proof.write_bytes(proof.read_bytes() + b" ")
        with self.assertRaisesRegex(
            PromotionBundleError,
            "hash mismatch",
        ):
            evaluate_promotion_bundles(
                self.root,
                self.frozen_path,
                [bundle],
            )

    def test_duplicate_bundle_is_rejected_as_duplicate_run_id(self) -> None:
        self._freeze()
        record = self._session_records()[0]
        self._create_state(*record)
        bundle = self.root / "bundle-one"
        capture_promotion_session(
            self.root,
            self.frozen_path,
            session_id=record[0],
            output_directory=bundle,
        )
        with self.assertRaisesRegex(
            PromotionBundleError,
            "more than once",
        ):
            evaluate_promotion_bundles(
                self.root,
                self.frozen_path,
                [bundle, bundle],
            )

    def test_finalize_is_exact_typed_and_must_follow_all_activity(self) -> None:
        self._freeze()
        record = self._session_records()[0]
        self._create_state(*record)
        with self.assertRaisesRegex(
            PromotionBundleError,
            "human_interventions",
        ):
            finalize_promotion_session(
                self.root,
                self.frozen_path,
                session_id=record[0],
                human_interventions=True,
                secret_or_flag_leaks=0,
            )

        parsed = parse_promotion_manifest(self.manifest)
        session = parsed.sessions[record[0]]
        state = self.store.load(session.identity, recover=False)
        finalized_at = state.metadata["evaluation_finalized_at"]

        def late_activity(current) -> None:
            current.runs.append(
                RunReference(
                    id="R-after-finalize",
                    base_revision=current.revision,
                    status=RunStatus.COMPLETED,
                    role="tool",
                    created_at=_later(finalized_at, 1),
                )
            )

        self.store.update(session.identity, late_activity)
        captured = capture_promotion_session(
            self.root,
            self.frozen_path,
            session_id=record[0],
            output_directory=self.root / "late-bundle",
        )
        self.assertFalse(captured["collection_complete"])
        self.assertIn(
            "activity_occurred_after_finalization",
            captured["collection_blockers"],
        )

    def test_fingerprint_change_after_prepare_blocks_capture(self) -> None:
        self._freeze()
        record = self._session_records()[0]
        self._create_state(*record)
        config_path = self.root / ".ctfos" / "engine.toml"
        atomic_write_text(
            config_path,
            set_runtime_image_digest(
                default_config_text(),
                "sha256:" + "4" * 64,
            ),
            mode=0o600,
        )
        with self.assertRaisesRegex(
            PromotionBundleError,
            "fingerprint",
        ):
            capture_promotion_session(
                self.root,
                self.frozen_path,
                session_id=record[0],
                output_directory=self.root / "wrong-fingerprint",
            )

    def test_missing_bundle_returns_closed_collector_and_gate(self) -> None:
        self._freeze()
        result = evaluate_promotion_bundles(
            self.root,
            self.frozen_path,
            [],
        )
        self.assertFalse(result["promotion_eligible"])
        self.assertFalse(result["complete_evidence"])
        self.assertTrue(
            any(
                blocker.startswith("missing_session_bundle:")
                for blocker in result["collector"]["blockers"]
            )
        )
        self.assertIn(
            "promotion_evidence_incomplete",
            result["blockers"],
        )

    def test_cli_routes_freeze_capture_and_closed_compare(self) -> None:
        record = self._session_records()[0]
        bundle = self.root / "cli-bundle"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            freeze_status = cli.main(
                [
                    "benchmark",
                    "freeze",
                    "--manifest",
                    str(self.manifest_path),
                    "--output",
                    str(self.frozen_path),
                ],
                root=self.root,
            )
        self._create_state(*record)
        with redirect_stdout(stdout), redirect_stderr(stderr):
            capture_status = cli.main(
                [
                    "benchmark",
                    "capture",
                    "--manifest",
                    str(self.frozen_path),
                    "--session",
                    record[0],
                    "--output",
                    str(bundle),
                ],
                root=self.root,
            )
            compare_status = cli.main(
                [
                    "benchmark",
                    "compare",
                    "--manifest",
                    str(self.frozen_path),
                    "--bundle",
                    str(bundle),
                ],
                root=self.root,
            )
        self.assertEqual(
            (freeze_status, capture_status, compare_status),
            (0, 0, 0),
            stderr.getvalue(),
        )
        decoder = json.JSONDecoder()
        values: list[object] = []
        remaining = stdout.getvalue().lstrip()
        while remaining:
            value, offset = decoder.raw_decode(remaining)
            values.append(value)
            remaining = remaining[offset:].lstrip()
        self.assertEqual(len(values), 3)
        self.assertTrue(values[0]["frozen"])
        self.assertTrue(values[1]["captured"])
        self.assertFalse(values[2]["promotion_eligible"])
        self.assertTrue(
            any(
                blocker.startswith("missing_session_bundle:")
                for blocker in values[2]["collector"]["blockers"]
            )
        )

    def test_complete_real_bundle_comparison_derives_required_metrics(
        self,
    ) -> None:
        self._freeze()
        bundles: list[Path] = []
        for record in self._session_records():
            self._create_state(*record)
            bundle = self.root / "bundles" / record[0]
            capture_promotion_session(
                self.root,
                self.frozen_path,
                session_id=record[0],
                output_directory=bundle,
            )
            bundles.append(bundle)

        result = evaluate_promotion_bundles(
            self.root,
            self.frozen_path,
            bundles,
        )

        self.assertTrue(result["promotion_eligible"], result["blockers"])
        self.assertEqual(
            result["decision"],
            "eligible_for_manual_promotion",
        )
        self.assertEqual(result["collector"]["blockers"], [])
        self.assertEqual(
            result["collector"]["verified_session_bundles"],
            84,
        )
        candidate = result["metrics"]["candidate"]
        self.assertEqual(candidate["overall"]["solve@1"]["rate"], 1.0)
        self.assertEqual(candidate["overall"]["pass^2/3"]["rate"], 1.0)
        self.assertEqual(
            candidate["by_split"]["live"][
                "median_time_to_first_valid_result"
            ]["seconds"],
            5.0,
        )
        self.assertEqual(
            candidate["live_hidden"][
                "median_time_to_first_valid_result"
            ]["seconds"],
            7.5,
        )
        self.assertEqual(
            candidate["overall"]["proof_pass_rate"]["rate"],
            1.0,
        )
        self.assertEqual(
            candidate["overall"]["human_interventions"],
            0,
        )
        self.assertEqual(
            candidate["live_hidden"]["category_floor"]["rate"],
            1.0,
        )
        self.assertTrue(
            result["comparisons"]["live_hidden_improvement"]
        )
        self.assertFalse(result["automatic_promotion"])
        self.assertFalse(result["automatic_submission"])
        self.assertFalse(result["automatic_challenge_switch"])


if __name__ == "__main__":
    unittest.main()
