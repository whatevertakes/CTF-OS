from __future__ import annotations

import tempfile
import unittest
import shlex
from pathlib import Path
from unittest import mock

from ctf_os import cli
from ctf_os.config import load_config
from ctf_os.contest_readiness import (
    challenge_diagnosis,
    challenge_readiness,
    contest_readiness,
)
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.models import (
    ChallengeIdentity,
    ExperimentStatus,
    RunReference,
    RunStatus,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.store import StateStore


def _ready_doctor() -> dict[str, object]:
    return {
        "ok": True,
        "warnings": [],
        "image": {"pin_status": "matched"},
        "managed_capabilities": {"status": "ready"},
    }


class ContestReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.identity = ChallengeIdentity("Demo CTF", "web", "Example")
        self.engine = ChallengeEngine(self.root)
        self.engine.add_challenge(
            self.identity,
            prompt="solve exactly this challenge",
            budget_seconds=3_600,
            state_schema_version=STATE_SCHEMA_VERSION,
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _state_bytes(self) -> tuple[bytes, bytes, bytes]:
        paths = self.engine.store.challenge_paths(self.identity)
        return (
            paths.state.read_bytes(),
            paths.previous_state.read_bytes(),
            paths.events.read_bytes(),
        )

    def test_contest_readiness_reads_snapshots_without_state_writes(self) -> None:
        before = self._state_bytes()

        report = contest_readiness(
            self.engine.store,
            load_config(self.root),
            _ready_doctor(),
            contest_id=self.identity.contest_id,
        )

        self.assertTrue(report["ok"], report)
        self.assertEqual(report["release"]["status"], "not_checked")
        self.assertEqual(len(report["challenges"]), 1)
        self.assertEqual(report["challenges"][0]["blockers"], [])
        self.assertFalse(report["authorities"]["automatic_remote_request"])
        self.assertFalse(
            report["authorities"]["automatic_canonical_state_mutation"]
        )
        self.assertTrue(
            report["authorities"]["local_host_diagnostic_processes_performed"]
        )
        self.assertEqual(before, self._state_bytes())

    def test_builtin_remote_requires_current_explicit_smoke_but_never_runs_it(
        self,
    ) -> None:
        state = self.engine.add_network_target(
            self.identity,
            "https://challenge.example:443",
            enforcement="builtin",
        )
        target = state.targets[-1]
        self.engine.select_network_target(self.identity, target.id)
        self.engine.register_experiment(
            self.identity,
            command=("python3", "-c", "print('remote')"),
            expected_observation="remote response",
            keep_if="response exists",
            drop_if="response is unavailable",
            network_target=target.endpoint,
        )
        before = self._state_bytes()
        state = self.engine.store.read_snapshot(self.identity)

        report = challenge_readiness(state)

        codes = {item["code"] for item in report["blockers"]}
        self.assertIn("selected_remote_target_preflight_stale", codes)
        self.assertIn("builtin_remote_smoke_missing", codes)
        self.assertTrue(
            any("target check" in item for item in report["next_commands"])
        )
        self.assertTrue(
            any("target smoke" in item for item in report["next_commands"])
        )
        parser = cli.build_parser()
        for command in report["next_commands"]:
            parser.parse_args(shlex.split(command)[1:])
        self.assertEqual(before, self._state_bytes())

    def test_stale_remote_experiment_binding_is_a_blocker(self) -> None:
        first = self.engine.add_network_target(
            self.identity,
            "https://first.example:443",
            enforcement="builtin",
        ).targets[-1]
        self.engine.select_network_target(self.identity, first.id)
        self.engine.register_experiment(
            self.identity,
            command=("python3", "-c", "print('remote')"),
            expected_observation="remote response",
            keep_if="response exists",
            drop_if="response is unavailable",
            network_target=first.endpoint,
        )
        second = self.engine.add_network_target(
            self.identity,
            "https://second.example:443",
            enforcement="builtin",
        ).targets[-1]
        self.engine.select_network_target(self.identity, second.id)

        report = challenge_readiness(
            self.engine.store.read_snapshot(self.identity)
        )

        self.assertFalse(report["ok"])
        self.assertIn(
            "remote_experiment_binding_stale",
            {item["code"] for item in report["blockers"]},
        )

    def test_exhausted_budget_is_a_blocker(self) -> None:
        def exhaust(state) -> None:
            state.budget.spent_seconds = state.budget.allocated_seconds or 0

        self.engine.store.update(self.identity, exhaust)

        report = challenge_readiness(
            self.engine.store.read_snapshot(self.identity)
        )

        self.assertFalse(report["ok"])
        self.assertIn(
            "budget_exhausted_or_invalid",
            {item["code"] for item in report["blockers"]},
        )
        self.assertTrue(
            any("budget-reset" in command for command in report["next_commands"])
        )

    def test_running_experiment_is_an_unreconciled_blocker(self) -> None:
        _state, experiment_id = self.engine.register_experiment(
            self.identity,
            command=("/bin/true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )

        def mark_running(state) -> None:
            experiment = next(
                item for item in state.experiments if item.id == experiment_id
            )
            experiment.status = ExperimentStatus.RUNNING

        self.engine.store.update(self.identity, mark_running)
        report = challenge_readiness(
            self.engine.store.read_snapshot(self.identity)
        )

        self.assertFalse(report["ok"])
        self.assertIn(
            "unreconciled_running_experiment",
            {item["code"] for item in report["blockers"]},
        )

    def test_running_run_and_analysis_lease_are_blockers(self) -> None:
        state = self.engine.store.read_snapshot(self.identity)
        state.runs.append(
            RunReference(
                id="run-orphan",
                base_revision=state.revision,
                status=RunStatus.RUNNING,
            )
        )
        state.extra["analysis_leases"] = [
            {
                "analysis_id": "analysis-" + ("a" * 32),
                "reason_code": None,
                "runtime_id": "analysis-runtime",
                "status": "cleanup_pending",
            }
        ]

        report = challenge_readiness(state)

        self.assertFalse(report["ok"])
        codes = {item["code"] for item in report["blockers"]}
        self.assertIn("unreconciled_running_run", codes)
        self.assertIn("analysis_lease_active_or_unreconciled", codes)

    def test_diagnosis_reads_snapshot_and_never_applies_recovery(self) -> None:
        before = self._state_bytes()

        report = challenge_diagnosis(self.engine.store, self.identity)

        self.assertEqual(report["kind"], "ctfos.challenge_diagnosis.v1")
        self.assertIsNone(report["latest_failure_capsule"])
        self.assertFalse(report["authorities"]["automatic_recovery"])
        self.assertFalse(
            report["authorities"]["automatic_challenge_tool_execution"]
        )
        self.assertEqual(before, self._state_bytes())

    def test_explicit_missing_contest_is_a_blocker(self) -> None:
        report = contest_readiness(
            self.engine.store,
            load_config(self.root),
            _ready_doctor(),
            contest_id="Typo CTF",
        )

        self.assertFalse(report["ok"])
        self.assertIn(
            "contest_not_found",
            {item["code"] for item in report["blockers"]},
        )

    def test_contest_scan_limit_fails_closed(self) -> None:
        contests = self.engine.store.contests_root
        (contests / "Second CTF").mkdir(parents=True)
        with mock.patch("ctf_os.contest_readiness.MAX_CONTESTS", 1):
            report = contest_readiness(
                self.engine.store,
                load_config(self.root),
                _ready_doctor(),
            )

        self.assertFalse(report["ok"])
        self.assertIn(
            "contest_scan_limit_reached",
            {item["code"] for item in report["blockers"]},
        )

    def test_challenge_scan_limit_and_invalid_entries_fail_closed(self) -> None:
        self.engine.add_challenge(
            ChallengeIdentity("Demo CTF", "web", "Second"),
            prompt="solve",
            budget_seconds=3_600,
        )
        invalid = self.engine.store.contests_root / "unexpected-file"
        invalid.write_text("not a contest", encoding="utf-8")
        with mock.patch("ctf_os.contest_readiness.MAX_CHALLENGES", 1):
            report = contest_readiness(
                self.engine.store,
                load_config(self.root),
                _ready_doctor(),
            )

        self.assertFalse(report["ok"])
        codes = {item["code"] for item in report["blockers"]}
        self.assertIn("invalid_contest_entry", codes)
        self.assertIn("challenge_scan_limit_reached", codes)

    def test_read_only_store_open_does_not_repair_or_touch_state_root(self) -> None:
        state_root = self.engine.store.root
        before = state_root.stat()
        state_bytes = self._state_bytes()

        reopened = StateStore.open_read_only(self.root)
        snapshot = reopened.read_snapshot(self.identity)

        after = state_root.stat()
        self.assertEqual(snapshot.identity, self.identity)
        self.assertEqual(before.st_mode, after.st_mode)
        self.assertEqual(before.st_mtime_ns, after.st_mtime_ns)
        self.assertEqual(before.st_ctime_ns, after.st_ctime_ns)
        self.assertEqual(state_bytes, self._state_bytes())

    def test_diagnosis_bounds_and_terminal_safes_failed_experiment_error(
        self,
    ) -> None:
        _state, experiment_id = self.engine.register_experiment(
            self.identity,
            command=("python3", "-c", "raise SystemExit(1)"),
            expected_observation="a failure",
            keep_if="never",
            drop_if="always",
        )

        def fail(state) -> None:
            experiment = next(
                item for item in state.experiments if item.id == experiment_id
            )
            experiment.status = ExperimentStatus.FAILED
            experiment.result = {"error": "sentinel\n" + ("x" * 2_000)}

        self.engine.store.update(self.identity, fail)
        before = self._state_bytes()

        report = challenge_diagnosis(self.engine.store, self.identity)

        terminal = report["latest_terminal_experiment"]
        self.assertEqual(terminal["status"], "failed")
        self.assertIn(r"sentinel\x0a", terminal["error"])
        self.assertNotIn("\n", terminal["error"])
        self.assertLessEqual(len(terminal["error"].encode("utf-8")), 515)
        self.assertEqual(before, self._state_bytes())


if __name__ == "__main__":
    unittest.main()
