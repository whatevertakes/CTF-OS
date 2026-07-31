from __future__ import annotations

import hashlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from ctf_os.codex import (
    BatchRunner,
    FifoModelCallLimiter,
    Role,
)
from ctf_os.config import load_config
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.managed import ManagedOrchestrator
from ctf_os.models import (
    ChallengeIdentity,
    ChallengeState,
    ChallengeStatus,
    HypothesisStatus,
    Provenance,
    RunStatus,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from tests.test_engine import (
    FakeSandbox,
    RoleExecutor,
    _role_for,
)
from tests.test_managed import IMAGE_DIGEST, ProbeRoleExecutor


class EvidenceProbeRoleExecutor(ProbeRoleExecutor):
    """Emit independent evidence and one bounded Builder artifact per wave."""

    artifact_payload = b"bounded partial sibling evidence"

    def __init__(self, *, invalid_roles: frozenset[Role] = frozenset()):
        super().__init__()
        self.invalid_roles = invalid_roles

    def run(self, command, *, cwd, timeout, on_stdout_line):
        role = _role_for(command)
        self.invalid_role = (
            role if role in self.invalid_roles else None
        )
        try:
            return super().run(
                command,
                cwd=cwd,
                timeout=timeout,
                on_stdout_line=on_stdout_line,
            )
        finally:
            self.invalid_role = None

    def _prepare_output_payload(
        self,
        *,
        command,
        cwd,
        role: Role,
        payload: dict[str, object],
    ) -> None:
        del command
        if role in self.invalid_roles or role is Role.CAPTAIN:
            return

        payload["hypotheses"] = [
            {
                "id": f"{role.value}-hypothesis",
                "claim": f"{role.value} has independent wave evidence",
                "evidence": ["obs-1"],
                "unknowns": ["whether the behavior survives replay"],
                "experiment": "replay one bounded input",
                "success_oracle": "the same observation is reproduced",
                "falsifier": "the replay does not reproduce it",
            }
        ]
        if role is Role.BUILDER:
            artifact_path = Path(cwd) / "sibling-evidence.bin"
            artifact_path.write_bytes(self.artifact_payload)
            payload["artifacts"] = [
                {
                    "path": artifact_path.name,
                    "sha256": hashlib.sha256(
                        self.artifact_payload
                    ).hexdigest(),
                    "purpose": "bounded sibling evidence",
                }
            ]


class PartialSemanticMergeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.identity = ChallengeIdentity(
            "Partial Barrier CTF",
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
        (incoming / "challenge.bin").write_bytes(b"\x7fELFpartial")

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

    def engine(self, executor) -> ChallengeEngine:
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
        return ChallengeEngine(
            self.root,
            config=config,
            batch_runner=BatchRunner(
                process_executor=executor,
                limiter=FifoModelCallLimiter(1),
                limiter_wait_timeout=2,
                max_schema_retries=0,
            ),
            sandbox_factory=lambda state, work, policy: FakeSandbox(work),
        )

    def add_challenge(self, engine: ChallengeEngine) -> None:
        engine.add_challenge(
            self.identity,
            prompt="solve this one challenge",
            state_schema_version=STATE_SCHEMA_VERSION,
        )

    def run_managed_cycle(
        self,
        executor: EvidenceProbeRoleExecutor,
        *,
        commit_patch=None,
    ) -> ChallengeState:
        engine = self.engine(executor)
        self.add_challenge(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        if commit_patch is None:
            return orchestrator.run_cycle(self.identity)
        with mock.patch.object(
            engine,
            "_commit_batch_results",
            side_effect=commit_patch(engine),
        ):
            return orchestrator.run_cycle(self.identity)

    @staticmethod
    def wave_records(state: ChallengeState):
        wave = state.waves[0]
        run_ids = set(wave.role_run_ids.values())
        runs = {
            run.id: run for run in state.runs if run.id in run_ids
        }
        facts = [
            fact
            for fact in state.facts
            if fact.source_run_id in run_ids
        ]
        hypotheses = [
            hypothesis
            for hypothesis in state.hypotheses
            if hypothesis.source_run_id in run_ids
        ]
        return wave, run_ids, runs, facts, hypotheses

    def test_one_invalid_role_merges_only_valid_sibling_evidence(self) -> None:
        executor = EvidenceProbeRoleExecutor(
            invalid_roles=frozenset({Role.FALSIFIER})
        )
        state = self.run_managed_cycle(executor)
        wave, run_ids, runs, facts, hypotheses = self.wave_records(state)
        valid_ids = {
            run.id
            for run in runs.values()
            if run.status is RunStatus.COMPLETED
        }
        invalid_ids = run_ids - valid_ids

        self.assertEqual(wave.status, "invalid")
        self.assertIs(state.status, ChallengeStatus.ACTIVE)
        self.assertEqual(
            {
                run.id
                for run in runs.values()
                if run.extra["partial_semantic_merge"] is True
            },
            valid_ids,
        )
        self.assertTrue(
            all(run.extra["semantic_merge"] is False for run in runs.values())
        )
        self.assertEqual(
            {fact.source_run_id for fact in facts},
            valid_ids,
        )
        self.assertEqual(
            {hypothesis.source_run_id for hypothesis in hypotheses},
            valid_ids,
        )
        self.assertFalse(
            any(fact.source_run_id in invalid_ids for fact in facts)
        )
        self.assertFalse(
            any(
                hypothesis.source_run_id in invalid_ids
                for hypothesis in hypotheses
            )
        )
        self.assertTrue(
            all(fact.provenance is Provenance.MODEL_CLAIMED for fact in facts)
        )
        facts_by_run = {
            fact.source_run_id: fact.id for fact in facts
        }
        self.assertTrue(
            all(
                hypothesis.status is HypothesisStatus.OPEN
                and hypothesis.evidence_fact_ids
                == [facts_by_run[hypothesis.source_run_id]]
                for hypothesis in hypotheses
            )
        )

        artifacts = [
            artifact
            for artifact in state.artifacts
            if artifact.source_run_id in run_ids
        ]
        self.assertEqual(len(artifacts), 1)
        artifact = artifacts[0]
        builder_id = wave.role_run_ids[Role.BUILDER.value]
        self.assertEqual(artifact.source_run_id, builder_id)
        self.assertEqual(artifact.size, len(executor.artifact_payload))
        self.assertEqual(
            artifact.sha256,
            hashlib.sha256(executor.artifact_payload).hexdigest(),
        )
        self.assertTrue(artifact.path.startswith("artifacts/snapshots/"))

        self.assertFalse(
            any(
                experiment.source_run_id in run_ids
                for experiment in state.experiments
            )
        )
        self.assertFalse(
            any(
                marker.run_id in run_ids
                for marker in state.progress_markers
            )
        )

    def test_all_invalid_roles_merge_no_semantics(self) -> None:
        executor = EvidenceProbeRoleExecutor(
            invalid_roles=frozenset(
                {
                    Role.BUILDER,
                    Role.FALSIFIER,
                    Role.REPRODUCER,
                }
            )
        )
        state = self.run_managed_cycle(executor)
        wave, run_ids, runs, facts, hypotheses = self.wave_records(state)

        self.assertEqual(wave.status, "invalid")
        self.assertEqual(facts, [])
        self.assertEqual(hypotheses, [])
        self.assertTrue(
            all(
                run.extra["partial_semantic_merge"] is False
                and run.extra["semantic_merge"] is False
                for run in runs.values()
            )
        )
        self.assertFalse(
            any(
                artifact.source_run_id in run_ids
                for artifact in state.artifacts
            )
        )
        self.assertFalse(
            any(
                experiment.source_run_id in run_ids
                for experiment in state.experiments
            )
        )

    def test_full_valid_barrier_preserves_full_wave_behavior(self) -> None:
        state = self.run_managed_cycle(EvidenceProbeRoleExecutor())
        wave, run_ids, runs, facts, hypotheses = self.wave_records(state)

        self.assertEqual(wave.status, "completed")
        self.assertEqual({fact.source_run_id for fact in facts}, run_ids)
        self.assertEqual(
            {hypothesis.source_run_id for hypothesis in hypotheses},
            run_ids,
        )
        self.assertTrue(
            all(
                run.extra["semantic_merge"] is True
                and run.extra["partial_semantic_merge"] is False
                for run in runs.values()
            )
        )
        self.assertTrue(
            any(
                experiment.source_run_id in run_ids
                for experiment in state.experiments
            )
        )
        self.assertEqual(
            {
                marker.run_id
                for marker in state.progress_markers
                if marker.run_id in run_ids
            },
            run_ids,
        )

    def test_stale_managed_barrier_fails_closed(self) -> None:
        def stale_commit_patch(engine: ChallengeEngine):
            original = engine._commit_batch_results

            def commit(base_state, results, **kwargs):
                if kwargs.get("semantic_barrier") is not True:
                    return original(base_state, results, **kwargs)
                stale = ChallengeState.from_dict(base_state.to_dict())
                result_ids = {
                    result.invocation.run_id for result in results
                }
                for run in stale.runs:
                    if run.id in result_ids:
                        run.configuration_epoch -= 1
                return original(stale, results, **kwargs)

            return commit

        state = self.run_managed_cycle(
            EvidenceProbeRoleExecutor(),
            commit_patch=stale_commit_patch,
        )
        _wave, run_ids, runs, facts, hypotheses = self.wave_records(state)

        self.assertEqual(facts, [])
        self.assertEqual(hypotheses, [])
        self.assertTrue(
            all(
                run.extra["partial_semantic_merge"] is False
                and run.extra["semantic_merge"] is False
                for run in runs.values()
            )
        )
        self.assertFalse(
            any(
                experiment.source_run_id in run_ids
                for experiment in state.experiments
            )
        )
        self.assertFalse(
            any(
                marker.run_id in run_ids
                for marker in state.progress_markers
            )
        )

    def test_non_managed_wave_behavior_is_unchanged(self) -> None:
        engine = self.engine(RoleExecutor())
        self.add_challenge(engine)

        outcome = engine.run_wave(self.identity, "discovery")
        state = engine.store.load(self.identity)
        run_ids = {
            result.invocation.run_id for result in outcome.results
        }

        self.assertEqual(
            {
                fact.source_run_id
                for fact in state.facts
                if fact.source_run_id in run_ids
            },
            run_ids,
        )
        self.assertEqual(
            {
                hypothesis.source_run_id
                for hypothesis in state.hypotheses
                if hypothesis.source_run_id in run_ids
            },
            run_ids,
        )
        self.assertEqual(
            {
                experiment.source_run_id
                for experiment in state.experiments
                if experiment.source_run_id in run_ids
            },
            run_ids,
        )
        self.assertTrue(
            all(
                run.extra["partial_semantic_merge"] is False
                for run in state.runs
                if run.id in run_ids
            )
        )
