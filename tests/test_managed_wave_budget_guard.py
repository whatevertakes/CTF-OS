from __future__ import annotations

import copy
import math
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from ctf_os.benchmark import CTF_OS_SYSTEM, THIN_SCAFFOLD
from ctf_os.budget import deadline_utc_after
from ctf_os.codex import BatchRunner, FifoModelCallLimiter, Role
from ctf_os.config import load_config
from ctf_os.engine.challenge import ChallengeEngine, EngineError
from ctf_os.managed import ManagedError, ManagedOrchestrator
from ctf_os.managed_budget import MANAGED_WAVE_BUDGET_GUARD_KEY
from ctf_os.models import (
    ChallengeIdentity,
    ChallengeStatus,
    ModelValidationError,
    SessionStatus,
)
from ctf_os.scaffold_binding import (
    SCAFFOLD_LAUNCH_METADATA_KEY,
    managed_command_contract_sha256,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from tests.test_engine import FakeSandbox
from tests.test_managed import ProbeRoleExecutor
from tests.test_scaffold_binding import IMAGE, prepared_metadata


class ManagedWaveBudgetIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.identity = ChallengeIdentity(
            "Managed Budget CTF",
            "rev",
            "one",
        )
        incoming = (
            self.root
            / "incoming"
            / self.identity.contest_id
            / self.identity.category
            / self.identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "challenge.bin").write_bytes(b"\x7fELFbudget")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    @staticmethod
    def capability(_digest: str):
        return {
            "ok": True,
            "schema_version": 2,
            "capabilities": {
                "convert": {},
                "sqlite_readonly": {},
                "z3": {},
                "ortools": {},
                "angr_python": {},
            },
        }

    @staticmethod
    def evaluation_fingerprint():
        metadata = prepared_metadata()
        return mock.Mock(
            tool_manifest_sha256=metadata[
                "evaluation_tool_manifest_sha256"
            ],
            image_sha256=metadata["evaluation_image_sha256"],
            model_config_sha256=metadata[
                "evaluation_model_config_sha256"
            ],
            engine_source_sha256=metadata[
                "evaluation_engine_source_sha256"
            ],
        )

    def engine(
        self,
        executor: ProbeRoleExecutor,
        *,
        provider_limit: int = 1,
        image_digest: str = "sha256:" + "b" * 64,
    ) -> ChallengeEngine:
        config = load_config(self.root)
        config = replace(
            config,
            resources=replace(
                config.resources,
                provider_max_concurrent_calls=provider_limit,
                max_standard_jobs=3,
            ),
            runtime=replace(
                config.runtime,
                image_digest=image_digest,
                managed_wave_queue_reserve_s=10.0,
                managed_wave_role_call_reserve_s=20.0,
                managed_wave_action_commit_reserve_s=30.0,
            ),
        )
        return ChallengeEngine(
            self.root,
            config=config,
            batch_runner=BatchRunner(
                process_executor=executor,
                limiter=FifoModelCallLimiter(provider_limit),
                limiter_wait_timeout=2,
                max_schema_retries=0,
            ),
            sandbox_factory=lambda state, work, policy: FakeSandbox(work),
        )

    def add_with_accounting_only_budget(
        self,
        engine: ChallengeEngine,
        seconds: int,
    ) -> None:
        engine.add_challenge(
            self.identity,
            prompt="solve this one challenge",
            budget_seconds=seconds,
            state_schema_version=STATE_SCHEMA_VERSION,
        )

        def remove_wall_deadline(state) -> None:
            state.budget.deadline_utc = None

        engine.store.update(self.identity, remove_wall_deadline)

    def test_insufficient_budget_preserves_captain_and_pauses_without_wave(
        self,
    ) -> None:
        executor = ProbeRoleExecutor()
        engine = self.engine(executor, provider_limit=1)
        # 10s admission + 3*20s calls + 30s action/commit = 100s.
        self.add_with_accounting_only_budget(engine, 99)
        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
            wall_clock=lambda: time.time(),
        ).run_cycle(self.identity)

        self.assertIs(state.status, ChallengeStatus.PAUSED)
        self.assertIsNone(state.active_managed_session_id)
        self.assertEqual(state.waves, [])
        self.assertEqual(executor.roles, [Role.CAPTAIN])
        self.assertEqual(len(state.cycles), 1)
        cycle = state.cycles[0]
        audit = cycle.extra[MANAGED_WAVE_BUDGET_GUARD_KEY]
        self.assertEqual(audit["decision"], "pause")
        self.assertEqual(
            audit["reason_code"],
            "insufficient_budget_for_wave",
        )
        self.assertEqual(audit["logical_role_count"], 3)
        self.assertEqual(audit["serial_provider_batches"], 3)
        self.assertEqual(audit["minimum_required_ms"], 100_000)
        self.assertEqual(audit["remaining_budget_ms"], 99_000)

        self.assertEqual(len(state.checkpoints), 1)
        capsule = state.checkpoints[0].failure_capsule
        self.assertIsNotNone(capsule)
        assert capsule is not None
        self.assertEqual(
            capsule.reason_code,
            "insufficient_budget_for_wave",
        )
        self.assertEqual(capsule.stage, "captain")
        self.assertTrue(capsule.unresolved_hypothesis_ids)
        self.assertTrue(capsule.next_experiment_ids)
        self.assertTrue(
            set(capsule.next_experiment_ids).issubset(
                {item.id for item in state.experiments}
            )
        )
        session = state.sessions[0]
        self.assertIs(session.status, SessionStatus.PAUSED)
        self.assertIn("remaining_ms=99000", session.stop_reason or "")
        state.validate()

    def test_exact_boundary_reserves_all_roles_even_with_serial_provider(
        self,
    ) -> None:
        executor = ProbeRoleExecutor()
        engine = self.engine(executor, provider_limit=1)
        self.add_with_accounting_only_budget(engine, 100)
        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        self.assertEqual(len(state.waves), 1)
        wave = state.waves[0]
        self.assertEqual(len(wave.role_run_ids), 3)
        self.assertEqual(
            set(wave.role_run_ids),
            {"builder", "falsifier", "reproducer"},
        )
        self.assertEqual(
            set(executor.roles),
            {
                Role.CAPTAIN,
                Role.BUILDER,
                Role.FALSIFIER,
                Role.REPRODUCER,
            },
        )
        audit = state.cycles[0].extra[
            MANAGED_WAVE_BUDGET_GUARD_KEY
        ]
        self.assertEqual(audit["decision"], "allow")
        self.assertEqual(audit["remaining_budget_ms"], 100_000)
        self.assertEqual(audit["minimum_required_ms"], 100_000)
        self.assertEqual(audit["serial_provider_batches"], 3)
        state.validate()

    def test_hostile_clock_fails_before_any_wave_reservation(self) -> None:
        executor = ProbeRoleExecutor()
        engine = self.engine(executor)
        self.add_with_accounting_only_budget(engine, 100)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
            wall_clock=lambda: math.nan,
        )
        _state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        before, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        with self.assertRaisesRegex(ManagedError, "clock must be finite"):
            orchestrator._reserve_wave(
                self.identity,
                session_id,
                cycle.id,
                "attack",
                enforce_budget_guard=True,
            )
        after = engine.store.load(self.identity)
        self.assertEqual(after.revision, before.revision)
        self.assertEqual(after.waves, [])
        self.assertNotIn(
            MANAGED_WAVE_BUDGET_GUARD_KEY,
            after.cycles[0].extra,
        )

    def test_injected_wall_clock_uses_strict_absolute_boundary(self) -> None:
        engine = self.engine(ProbeRoleExecutor())
        self.add_with_accounting_only_budget(engine, 1_000)

        def add_absolute_deadline(state) -> None:
            state.budget.deadline_utc = deadline_utc_after(
                100,
                now_epoch=1_000.0,
            )

        engine.store.update(self.identity, add_absolute_deadline)
        state = engine.store.load(self.identity)
        exact = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
            wall_clock=lambda: 1_000.0,
        )._managed_wave_budget_guard(state, "attack")
        self.assertEqual(exact["remaining_budget_ms"], 100_000)
        self.assertEqual(exact["decision"], "allow")

        one_millisecond_late = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
            wall_clock=lambda: 1_000.001,
        )._managed_wave_budget_guard(state, "attack")
        self.assertEqual(
            one_millisecond_late["remaining_budget_ms"],
            99_999,
        )
        self.assertEqual(one_millisecond_late["decision"], "pause")

    def test_canonical_state_rejects_mutated_or_orphaned_pause_guard(
        self,
    ) -> None:
        engine = self.engine(ProbeRoleExecutor())
        self.add_with_accounting_only_budget(engine, 99)
        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        mutated = copy.deepcopy(state)
        mutated.cycles[0].extra[
            MANAGED_WAVE_BUDGET_GUARD_KEY
        ]["logical_role_count"] = 2
        with self.assertRaisesRegex(
            ModelValidationError,
            "managed wave budget guard",
        ):
            mutated.validate()

        orphaned = copy.deepcopy(state)
        orphaned.cycles[0].extra.pop(
            MANAGED_WAVE_BUDGET_GUARD_KEY
        )
        with self.assertRaisesRegex(
            ModelValidationError,
            "capsule lacks",
        ):
            orphaned.validate()

    def test_prepared_evaluation_records_managed_scaffold_once_before_session(
        self,
    ) -> None:
        engine = self.engine(
            ProbeRoleExecutor(),
            image_digest=IMAGE,
        )
        self.add_with_accounting_only_budget(engine, 100)

        def prepare(state) -> None:
            metadata = prepared_metadata(CTF_OS_SYSTEM)
            metadata["source_manifest_sha256"] = state.metadata[
                "source_manifest_sha256"
            ]
            state.metadata.update(metadata)

        engine.store.update(self.identity, prepare)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        with mock.patch(
            "ctf_os.promotion_bundles.local_execution_fingerprint",
            return_value=self.evaluation_fingerprint(),
        ):
            state, session_id = orchestrator._reserve_session(
                self.identity,
                "S-evaluation",
                thread_continuity_policy="fresh",
            )
        record = state.metadata[SCAFFOLD_LAUNCH_METADATA_KEY]
        expected_contract = managed_command_contract_sha256(
            model_id=engine.config.models.captain,
            captain_effort=engine.config.models.captain_effort,
            worker_effort=engine.config.models.worker_effort,
            thread_continuity_policy="fresh",
        )
        self.assertEqual(
            record["command_contract_sha256"],
            expected_contract,
        )
        self.assertEqual(record["arm"], CTF_OS_SYSTEM)

        resumed, resumed_id = orchestrator._reserve_session(
            self.identity,
            session_id,
            thread_continuity_policy="fresh",
        )
        self.assertEqual(resumed_id, session_id)
        self.assertEqual(
            resumed.metadata[SCAFFOLD_LAUNCH_METADATA_KEY],
            record,
        )

        def tamper_launch(state) -> None:
            state.metadata[SCAFFOLD_LAUNCH_METADATA_KEY]["arm"] = (
                THIN_SCAFFOLD
            )

        engine.store.update(self.identity, tamper_launch)
        with self.assertRaisesRegex(
            ManagedError,
            "scaffold launch is invalid",
        ):
            orchestrator._reserve_session(
                self.identity,
                session_id,
                thread_continuity_policy="fresh",
            )

        def restore_launch(state) -> None:
            state.metadata[SCAFFOLD_LAUNCH_METADATA_KEY] = copy.deepcopy(
                record
            )

        engine.store.update(self.identity, restore_launch)

        def terminalize(state) -> None:
            session = state.sessions[0]
            session.status = SessionStatus.PAUSED
            session.end_revision = state.revision + 1
            session.ended_at = "2026-07-31T00:00:00Z"
            state.active_managed_session_id = None

        engine.store.update(self.identity, terminalize)
        with self.assertRaisesRegex(
            EngineError,
            "already launched",
        ):
            orchestrator._reserve_session(
                self.identity,
                "S-second-evaluation",
            )

    def test_prepared_thin_arm_rejects_managed_session_before_creation(
        self,
    ) -> None:
        engine = self.engine(
            ProbeRoleExecutor(),
            image_digest=IMAGE,
        )
        self.add_with_accounting_only_budget(engine, 100)

        def prepare(state) -> None:
            metadata = prepared_metadata(THIN_SCAFFOLD)
            metadata["source_manifest_sha256"] = state.metadata[
                "source_manifest_sha256"
            ]
            state.metadata.update(metadata)

        engine.store.update(self.identity, prepare)
        with (
            mock.patch(
                "ctf_os.promotion_bundles.local_execution_fingerprint",
                return_value=self.evaluation_fingerprint(),
            ),
            self.assertRaisesRegex(EngineError, "arm does not match"),
        ):
            ManagedOrchestrator(
                engine,
                capability_probe=self.capability,
            )._reserve_session(
                self.identity,
                "S-wrong-arm",
            )
        state = engine.store.load(self.identity)
        self.assertEqual(state.sessions, [])
        self.assertNotIn(
            SCAFFOLD_LAUNCH_METADATA_KEY,
            state.metadata,
        )


if __name__ == "__main__":
    unittest.main()
