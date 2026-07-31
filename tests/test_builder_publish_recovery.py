from __future__ import annotations

import errno
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import ctf_os.workspace_publish as workspace_publish_module
from ctf_os.codex import BatchRunner, FifoModelCallLimiter, Role
from ctf_os.config import load_config
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.resume_capsule import render_resume_capsule
from ctf_os.managed import ManagedError, ManagedOrchestrator
from ctf_os.models import (
    ChallengeIdentity,
    ChallengeStatus,
    ExperimentStatus,
    RunStatus,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.workspace_publish import MAX_PUBLISH_BYTES
from tests.test_engine import FakeSandbox
from tests.test_managed import IMAGE_DIGEST, ProbeRoleExecutor


class BuilderPublishExecutor(ProbeRoleExecutor):
    def __init__(
        self,
        *,
        proposals: tuple[tuple[str, bytes | None], ...],
        symlink_escape: tuple[str, Path] | None = None,
        fifo_paths: tuple[str, ...] = (),
        sparse_sizes: dict[str, int] | None = None,
    ) -> None:
        super().__init__()
        self.proposals = proposals
        self.symlink_escape = symlink_escape
        self.fifo_paths = frozenset(fifo_paths)
        self.sparse_sizes = dict(sparse_sizes or {})

    def _prepare_output_payload(
        self,
        *,
        command,
        cwd,
        role: Role,
        payload: dict[str, object],
    ) -> None:
        del command
        if role is not Role.BUILDER:
            return
        workspace = Path(cwd)
        if self.symlink_escape is not None:
            name, destination = self.symlink_escape
            os.symlink(destination, workspace / name)
        for relative, content in self.proposals:
            payload["actions"].append(
                {
                    "kind": "write_artifact",
                    "description": "publish one bounded Builder artifact",
                    "command": None,
                    "artifact_path": relative,
                    "hypothesis_ids": [],
                    "expected_observation": (
                        "the staged regular file is published"
                    ),
                    "keep_if": "the canonical workspace hash is recorded",
                    "drop_if": "the staged source is rejected",
                    "timeout_seconds": 30,
                    "resource_class": "light",
                    "network_target_id": None,
                    "network_target_generation": None,
                }
            )
            if relative in self.fifo_paths:
                target = workspace / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                os.mkfifo(target)
            elif relative in self.sparse_sizes:
                target = workspace / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.touch()
                os.truncate(target, self.sparse_sizes[relative])
            elif content is not None:
                target = workspace / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)


class BuilderPublishRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.identity = ChallengeIdentity(
            "Builder Publish",
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
        (incoming / "challenge.bin").write_bytes(b"\x7fELFmanaged")

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

    def engine(self, executor: BuilderPublishExecutor) -> ChallengeEngine:
        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                image_digest=IMAGE_DIGEST,
            ),
            resources=replace(
                config.resources,
                provider_max_concurrent_calls=1,
                max_standard_jobs=3,
            ),
        )
        runner = BatchRunner(
            process_executor=executor,
            limiter=FifoModelCallLimiter(1),
            limiter_wait_timeout=2,
            max_schema_retries=0,
        )
        return ChallengeEngine(
            self.root,
            config=config,
            batch_runner=runner,
            sandbox_factory=lambda state, work, policy: FakeSandbox(work),
        )

    def run_one(
        self,
        executor: BuilderPublishExecutor,
    ) -> tuple[ChallengeEngine, ManagedOrchestrator, object]:
        engine = self.engine(executor)
        engine.add_challenge(
            self.identity,
            prompt="solve this one challenge",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        return engine, orchestrator, orchestrator.run_cycle(self.identity)

    def assert_rejected_checkpoint(
        self,
        engine: ChallengeEngine,
        state,
        *,
        code: str,
        ordinal: int,
    ) -> None:
        self.assertIsNot(state.status, ChallengeStatus.NEEDS_HUMAN)
        self.assertIsNotNone(state.active_managed_session_id)
        capsule = state.checkpoints[-1].failure_capsule
        self.assertIsNotNone(capsule)
        assert capsule is not None
        self.assertEqual(capsule.reason_code, "builder_publish_rejected")
        wave = state.waves[-1]
        builder = next(
            run
            for run in state.runs
            if run.id == wave.role_run_ids[Role.BUILDER.value]
        )
        self.assertIs(builder.status, RunStatus.COMPLETED)
        self.assertEqual(
            builder.extra["managed_rejection_v1"]["issues"],
            [
                {
                    "code": code,
                    "kind": "artifact_publication",
                    "proposal_ordinal": ordinal,
                }
            ],
        )
        wave_run_ids = set(wave.role_run_ids.values())
        wave_experiments = [
            experiment
            for experiment in state.experiments
            if experiment.source_run_id in wave_run_ids
        ]
        self.assertTrue(wave_experiments)
        self.assertTrue(
            all(
                experiment.status is ExperimentStatus.CANCELLED
                for experiment in wave_experiments
            )
        )
        self.assertFalse(
            set(capsule.next_experiment_ids).intersection(
                experiment.id for experiment in wave_experiments
            )
        )
        self.assertEqual(state.cycles[-1].selected_action_ids, [])
        resume = render_resume_capsule(
            state,
            state_path=engine.store.challenge_paths(self.identity).state,
        ).text
        self.assertIn(code, resume)
        self.assertIn(f'"proposal_ordinal":{ordinal}', resume)

    def test_missing_source_checkpoints_without_running_wave_actions(self):
        canary = "nested/MISSING-CANARY-do-not-echo.py"
        engine, _orchestrator, state = self.run_one(
            BuilderPublishExecutor(
                proposals=((canary, None),),
            )
        )

        self.assert_rejected_checkpoint(
            engine,
            state,
            code="artifact_source_missing",
            ordinal=1,
        )
        challenge_paths = engine.store.challenge_paths(self.identity)
        self.assertFalse(
            (
                challenge_paths.artifacts
                / "workspace"
                / "nested"
            ).exists()
        )
        resume = render_resume_capsule(
            state,
            state_path=challenge_paths.state,
        ).text
        self.assertNotIn(canary, resume)
        self.assertNotIn("No such file", resume)

    def test_success_prefix_is_preserved_when_second_proposal_fails(self):
        canary = "missing/CANARY-second.py"
        engine, _orchestrator, state = self.run_one(
            BuilderPublishExecutor(
                proposals=(
                    ("solve.py", b"print('prefix')\n"),
                    (canary, None),
                ),
            )
        )

        self.assert_rejected_checkpoint(
            engine,
            state,
            code="artifact_source_missing",
            ordinal=2,
        )
        paths = engine.store.challenge_paths(self.identity)
        self.assertEqual(
            (paths.artifacts / "workspace" / "solve.py").read_bytes(),
            b"print('prefix')\n",
        )
        self.assertEqual(state.workspace_revision, 1)
        self.assertEqual(len(state.workspace_publishes), 1)
        self.assertEqual(
            state.workspace_publishes[0].destination,
            "solve.py",
        )
        resume = render_resume_capsule(
            state,
            state_path=paths.state,
        ).text
        self.assertNotIn(canary, resume)

    def test_intermediate_stage_symlink_is_rejected_without_escape(self):
        outside = self.root / "outside"
        outside.mkdir()
        canary = outside / "secret.txt"
        canary.write_bytes(b"outside-canary")
        engine, _orchestrator, state = self.run_one(
            BuilderPublishExecutor(
                proposals=(("escape/secret.txt", None),),
                symlink_escape=("escape", outside),
            )
        )

        self.assert_rejected_checkpoint(
            engine,
            state,
            code="artifact_source_unsafe",
            ordinal=1,
        )
        self.assertEqual(canary.read_bytes(), b"outside-canary")
        self.assertFalse(
            (
                engine.store.challenge_paths(self.identity).artifacts
                / "workspace"
                / "escape"
                / "secret.txt"
            ).exists()
        )

    def test_fifo_source_is_rejected_without_blocking(self):
        relative = "pipe/result"
        engine, _orchestrator, state = self.run_one(
            BuilderPublishExecutor(
                proposals=((relative, None),),
                fifo_paths=(relative,),
            )
        )

        self.assert_rejected_checkpoint(
            engine,
            state,
            code="artifact_source_unsafe",
            ordinal=1,
        )

    def test_unreported_symlink_remains_a_wave_storage_failure(self):
        outside = self.root / "unreported-outside"
        outside.mkdir()
        engine, _orchestrator, state = self.run_one(
            BuilderPublishExecutor(
                proposals=(),
                symlink_escape=("unreported", outside),
            )
        )

        capsule = state.checkpoints[-1].failure_capsule
        self.assertIsNotNone(capsule)
        assert capsule is not None
        self.assertEqual(capsule.reason_code, "analysis_wave_invalid")
        wave = state.waves[-1]
        builder = next(
            run
            for run in state.runs
            if run.id == wave.role_run_ids[Role.BUILDER.value]
        )
        self.assertIs(builder.status, RunStatus.FAILED)
        self.assertTrue(
            any(
                failure["kind"] == "workspace_storage_postcondition"
                for failure in builder.extra["failures"]
            )
        )

    def test_oversize_sparse_source_is_rejected_pre_intent(self):
        relative = "large/result.bin"
        engine, _orchestrator, state = self.run_one(
            BuilderPublishExecutor(
                proposals=((relative, None),),
                sparse_sizes={
                    relative: MAX_PUBLISH_BYTES + 1,
                },
            )
        )

        self.assert_rejected_checkpoint(
            engine,
            state,
            code="artifact_size_limit_exceeded",
            ordinal=1,
        )
        paths = engine.store.challenge_paths(self.identity)
        self.assertFalse(
            (paths.artifacts / "workspace" / "large").exists()
        )
        intent_root = paths.runtime / "workspace-publish-intents"
        self.assertFalse(
            intent_root.exists() and any(intent_root.iterdir())
        )

    def test_unexpected_source_oserror_remains_fatal(self):
        executor = BuilderPublishExecutor(
            proposals=(("solve.py", b"print('ready')\n"),),
        )
        engine = self.engine(executor)
        engine.add_challenge(
            self.identity,
            prompt="solve this one challenge",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        with (
            mock.patch.object(
                workspace_publish_module,
                "_open_builder_stage",
                side_effect=OSError(errno.EIO, "IO-CANARY"),
            ),
            self.assertRaisesRegex(ManagedError, "IO-CANARY"),
        ):
            orchestrator.run_cycle(self.identity)
        state = engine.store.load(self.identity)
        self.assertIs(state.status, ChallengeStatus.NEEDS_HUMAN)

    def test_canonical_parent_symlink_is_fatal_without_escape(self):
        outside = self.root / "canonical-outside"
        outside.mkdir()
        executor = BuilderPublishExecutor(
            proposals=(("escape/solve.py", b"outside-write-canary"),),
        )
        engine = self.engine(executor)
        engine.add_challenge(
            self.identity,
            prompt="solve this one challenge",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        paths = engine.store.challenge_paths(self.identity)
        canonical_root = paths.artifacts / "workspace"
        canonical_root.mkdir(parents=True)
        os.symlink(outside, canonical_root / "escape")
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )

        with self.assertRaises(ManagedError):
            orchestrator.run_cycle(self.identity)
        state = engine.store.load(self.identity)
        self.assertIs(state.status, ChallengeStatus.NEEDS_HUMAN)
        self.assertFalse((outside / "solve.py").exists())

    def test_rejection_state_update_oserror_remains_fatal(self):
        executor = BuilderPublishExecutor(
            proposals=(("missing.py", None),),
        )
        engine = self.engine(executor)
        engine.add_challenge(
            self.identity,
            prompt="solve this one challenge",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        real_update = engine.store.update

        def fail_rejection_update(*args, **kwargs):
            mutator = args[1] if len(args) > 1 else kwargs.get("mutator")
            if getattr(mutator, "__name__", "") == "record_rejection":
                raise OSError("STORE-CANARY fatal")
            return real_update(*args, **kwargs)

        with (
            mock.patch.object(
                engine.store,
                "update",
                side_effect=fail_rejection_update,
            ),
            self.assertRaisesRegex(ManagedError, "STORE-CANARY"),
        ):
            orchestrator.run_cycle(self.identity)
        state = engine.store.load(self.identity)
        self.assertIs(state.status, ChallengeStatus.NEEDS_HUMAN)


if __name__ == "__main__":
    unittest.main()
