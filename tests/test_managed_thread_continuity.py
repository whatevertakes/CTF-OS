from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest import mock

from ctf_os import cli
from ctf_os.codex import BatchRunner, FifoModelCallLimiter, Role
from ctf_os.config import load_config
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.managed import ManagedError, ManagedOrchestrator
from ctf_os.managed_continuity import (
    THREAD_CONTINUITY_RUN_KEY,
    THREAD_CONTINUITY_SESSION_KEY,
)
from ctf_os.models import (
    ChallengeIdentity,
    ModelValidationError,
    RunStatus,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.store.atomic import read_json
from tests.test_builder_publish_recovery import BuilderPublishExecutor
from tests.test_engine import FakeSandbox, _role_for
from tests.test_managed import IMAGE_DIGEST, ProbeRoleExecutor


class ThreadedProbeRoleExecutor(ProbeRoleExecutor):
    """Valid fake provider that exposes opaque thread events and cwd usage."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.commands: list[tuple[Role, tuple[str, ...], Path, str]] = []

    def run(self, command, *, cwd, timeout, on_stdout_line):
        role = _role_for(command)
        self.commands.append(
            (role, tuple(command.argv), Path(cwd), command.stdin)
        )
        on_stdout_line(
            json.dumps(
                {
                    "type": "thread.started",
                    "thread_id": f"thread-{role.value}-opaque",
                }
            )
            + "\n"
        )
        return super().run(
            command,
            cwd=cwd,
            timeout=timeout,
            on_stdout_line=on_stdout_line,
        )


class ManagedThreadContinuityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.identity = ChallengeIdentity(
            "Continuity CTF",
            "rev",
            "single",
        )
        incoming = (
            self.root
            / "incoming"
            / self.identity.contest_id
            / self.identity.category
            / self.identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "challenge.bin").write_bytes(
            b"\x7fELFcontinuity"
        )

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

    def engine(
        self,
        executor: ProbeRoleExecutor,
    ) -> ChallengeEngine:
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

    def add(self, engine: ChallengeEngine) -> None:
        engine.add_challenge(
            self.identity,
            prompt="solve one challenge",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        engine.refresh_ingest(self.identity)

    @staticmethod
    def audit(run) -> dict[str, object]:
        value = run.extra[THREAD_CONTINUITY_RUN_KEY]
        assert isinstance(value, dict)
        return value

    def test_default_fresh_and_forced_fresh_roles_are_explicit(self) -> None:
        engine = self.engine(ProbeRoleExecutor())
        self.add(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        session = next(item for item in state.sessions if item.id == session_id)
        metadata = session.extra[THREAD_CONTINUITY_SESSION_KEY]
        self.assertEqual(metadata["policy"], "fresh")
        self.assertEqual(
            len(metadata["configuration_fingerprint_sha256"]),
            64,
        )

        state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        captain = next(
            item for item in state.runs if item.id == cycle.captain_run_id
        )
        self.assertEqual(
            self.audit(captain),
            {
                **self.audit(captain),
                "policy": "fresh",
                "decision": "fresh",
                "reason": "policy_fresh",
                "source_run_id": None,
                "thread_id_sha256": None,
                "stable_lane": False,
                "lane_identity_sha256": None,
                "lane_path_identity_sha256": None,
                "workspace_owner_run_id": None,
            },
        )

        state, _wave, role_runs = orchestrator._reserve_wave(
            self.identity,
            session_id,
            cycle.id,
            "proof",
        )
        for role, run_id in role_runs.items():
            audit = self.audit(
                next(item for item in state.runs if item.id == run_id)
            )
            self.assertEqual(audit["decision"], "fresh")
            self.assertEqual(
                audit["reason"],
                "proof_wave_forced_fresh",
            )
            self.assertFalse(audit["stable_lane"], role.value)

    def test_role_lane_reuses_only_eligible_exact_lanes_and_is_raw_free(
        self,
    ) -> None:
        executor = ThreadedProbeRoleExecutor(
            captain_stage="attack",
            invalid_role=Role.FALSIFIER,
        )
        engine = self.engine(executor)
        self.add(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )

        first = orchestrator.run_cycle(
            self.identity,
            thread_continuity_policy="role_lane",
        )
        executor.invalid_role = None
        second = orchestrator.run_cycle(
            self.identity,
            thread_continuity_policy="role_lane",
        )
        self.assertEqual(
            first.active_managed_session_id,
            second.active_managed_session_id,
        )
        session_id = second.active_managed_session_id
        self.assertIsNotNone(session_id)
        session = next(
            item for item in second.sessions if item.id == session_id
        )
        self.assertEqual(
            session.extra[THREAD_CONTINUITY_SESSION_KEY]["policy"],
            "role_lane",
        )

        runs_by_role: dict[str, list] = {}
        for run in second.runs:
            if run.session_id == session_id:
                runs_by_role.setdefault(run.role or "", []).append(run)
        for role in (Role.CAPTAIN, Role.BUILDER):
            self.assertGreaterEqual(len(runs_by_role[role.value]), 2)
            source, resumed = runs_by_role[role.value][-2:]
            audit = self.audit(resumed)
            self.assertEqual(audit["decision"], "resume")
            self.assertEqual(
                audit["reason"],
                "resume_previous_completed_lane",
            )
            self.assertEqual(audit["source_run_id"], source.id)
            self.assertEqual(
                audit["thread_id_sha256"],
                hashlib.sha256(
                    f"thread-{role.value}-opaque".encode("ascii")
                ).hexdigest(),
            )
            self.assertEqual(
                audit["workspace_owner_run_id"],
                self.audit(source)["workspace_owner_run_id"],
            )
            self.assertNotIn("thread_id", resumed.extra)

        for role in (Role.FALSIFIER, Role.REPRODUCER):
            audit = self.audit(runs_by_role[role.value][-1])
            self.assertEqual(audit["decision"], "fresh")
            self.assertEqual(
                audit["reason"],
                "role_lane_ineligible_role",
            )
            self.assertFalse(audit["stable_lane"])

        commands_by_role: dict[Role, list[tuple[tuple[str, ...], Path, str]]] = {}
        for role, argv, cwd, prompt in executor.commands:
            commands_by_role.setdefault(role, []).append(
                (argv, cwd, prompt)
            )
        for role in (Role.CAPTAIN, Role.BUILDER):
            first_command, resumed_command = commands_by_role[role][-2:]
            self.assertNotIn("resume", first_command[0])
            self.assertIn("resume", resumed_command[0])
            resume_index = resumed_command[0].index("resume")
            self.assertEqual(
                resumed_command[0][resume_index + 1],
                f"thread-{role.value}-opaque",
            )
            self.assertEqual(first_command[1], resumed_command[1])
            self.assertNotIn(
                f"thread-{role.value}-opaque",
                resumed_command[2],
            )
        for role in (Role.FALSIFIER, Role.REPRODUCER):
            self.assertNotIn("resume", commands_by_role[role][-1][0])
            self.assertNotEqual(
                commands_by_role[role][-2][1],
                commands_by_role[role][-1][1],
            )

        resumed_captain = runs_by_role[Role.CAPTAIN.value][-1]
        request_path = (
            engine.store.challenge_paths(self.identity).root
            / str(resumed_captain.request_path)
        )
        request = read_json(request_path)
        self.assertIn("context_path", request)
        self.assertIn("context_sha256", request)
        self.assertEqual(
            request[THREAD_CONTINUITY_RUN_KEY],
            self.audit(resumed_captain),
        )
        raw_thread = "thread-captain-opaque"
        self.assertNotIn(raw_thread, json.dumps(request, sort_keys=True))
        state_text = engine.store.challenge_paths(
            self.identity
        ).state.read_text(encoding="utf-8")
        self.assertNotIn(raw_thread, state_text)
        source_captain = runs_by_role[Role.CAPTAIN.value][-2]
        secret = read_json(
            engine.store.challenge_paths(self.identity).root
            / source_captain.extra["thread_secret_path"]
        )
        self.assertEqual(secret["thread_id"], raw_thread)
        second.validate()

    def test_first_role_lane_builder_publishes_from_stable_workspace(
        self,
    ) -> None:
        executor = BuilderPublishExecutor(
            proposals=(("solver.py", b"print('stable lane')\n"),),
        )
        engine = self.engine(executor)
        self.add(engine)
        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(
            self.identity,
            thread_continuity_policy="role_lane",
        )
        wave = state.waves[-1]
        builder = next(
            item
            for item in state.runs
            if item.id == wave.role_run_ids[Role.BUILDER.value]
        )
        self.assertTrue(self.audit(builder)["stable_lane"])
        self.assertEqual(
            (
                engine.store.challenge_paths(self.identity).artifacts
                / "workspace"
                / "solver.py"
            ).read_bytes(),
            b"print('stable lane')\n",
        )

    def test_captain_policy_and_proof_wave_never_resume_validators(
        self,
    ) -> None:
        engine = self.engine(ProbeRoleExecutor())
        self.add(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
            thread_continuity_policy="captain_lane",
        )
        state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        captain = next(
            item for item in state.runs if item.id == cycle.captain_run_id
        )
        self.assertTrue(self.audit(captain)["stable_lane"])
        state, _wave, discovery_runs = orchestrator._reserve_wave(
            self.identity,
            session_id,
            cycle.id,
            "discovery",
        )
        for run_id in discovery_runs.values():
            audit = self.audit(
                next(item for item in state.runs if item.id == run_id)
            )
            self.assertEqual(
                audit["reason"],
                "captain_lane_non_captain",
            )
            self.assertFalse(audit["stable_lane"])

        second_identity = ChallengeIdentity(
            self.identity.contest_id,
            self.identity.category,
            "proof",
        )
        incoming = (
            self.root
            / "incoming"
            / second_identity.contest_id
            / second_identity.category
            / second_identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "challenge.bin").write_bytes(b"\x7fELFproof")
        engine.add_challenge(
            second_identity,
            prompt="prove",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        engine.refresh_ingest(second_identity)
        state, proof_session = orchestrator._reserve_session(
            second_identity,
            None,
            thread_continuity_policy="role_lane",
        )
        state, proof_cycle = orchestrator._reserve_cycle(
            second_identity,
            proof_session,
        )
        state, _wave, proof_runs = orchestrator._reserve_wave(
            second_identity,
            proof_session,
            proof_cycle.id,
            "proof",
        )
        for run_id in proof_runs.values():
            audit = self.audit(
                next(item for item in state.runs if item.id == run_id)
            )
            self.assertEqual(
                audit["reason"],
                "proof_wave_forced_fresh",
            )
            self.assertEqual(audit["decision"], "fresh")
            self.assertFalse(audit["stable_lane"])

    def test_policy_config_and_cross_scope_tampering_fail_closed(self) -> None:
        executor = ThreadedProbeRoleExecutor(captain_stage="attack")
        engine = self.engine(executor)
        self.add(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        first = orchestrator.run_cycle(
            self.identity,
            thread_continuity_policy="role_lane",
        )
        with self.assertRaisesRegex(ManagedError, "pinned"):
            orchestrator._reserve_session(
                self.identity,
                first.active_managed_session_id,
                thread_continuity_policy="fresh",
            )
        original_config = engine.config
        engine.config = replace(
            engine.config,
            models=replace(
                engine.config.models,
                captain="different-frontier-model",
            ),
        )
        with self.assertRaisesRegex(ManagedError, "pinned"):
            orchestrator._reserve_session(
                self.identity,
                first.active_managed_session_id,
                thread_continuity_policy="role_lane",
            )
        engine.config = original_config

        tampered = copy.deepcopy(first)
        session = next(
            item
            for item in tampered.sessions
            if item.id == tampered.active_managed_session_id
        )
        session.extra[THREAD_CONTINUITY_SESSION_KEY]["policy"] = "fresh"
        with self.assertRaisesRegex(
            ModelValidationError,
            "configuration fingerprint",
        ):
            tampered.validate()

        state, cycle = orchestrator._reserve_cycle(
            self.identity,
            first.active_managed_session_id,
        )
        captain = next(
            item for item in state.runs if item.id == cycle.captain_run_id
        )
        audit = self.audit(captain)
        self.assertEqual(audit["decision"], "resume")
        builder = next(
            item
            for item in state.runs
            if item.session_id == first.active_managed_session_id
            and item.role == Role.BUILDER.value
            and item.status is RunStatus.COMPLETED
        )
        hostile = copy.deepcopy(state)
        hostile_captain = next(
            item for item in hostile.runs if item.id == captain.id
        )
        hostile_audit = self.audit(hostile_captain)
        hostile_audit["source_run_id"] = builder.id
        hostile_audit["thread_id_sha256"] = builder.extra[
            "produced_thread_id_sha256"
        ]
        with self.assertRaisesRegex(
            ModelValidationError,
            "resume source",
        ):
            hostile.validate()

        scope_state = first
        source = next(
            item
            for item in reversed(scope_state.runs)
            if item.role == Role.CAPTAIN.value
            and item.status is RunStatus.COMPLETED
        )
        session = next(
            item
            for item in scope_state.sessions
            if item.id == scope_state.active_managed_session_id
        )
        cases = (
            ("session_id", "cross-session", "prior_session_mismatch"),
            (
                "configuration_epoch",
                scope_state.configuration_epoch + 1,
                "prior_configuration_mismatch",
            ),
            ("model", "other-model", "prior_model_mismatch"),
        )
        for attribute, value, expected_reason in cases:
            with self.subTest(scope=attribute):
                scoped = copy.deepcopy(scope_state)
                scoped_session = next(
                    item
                    for item in scoped.sessions
                    if item.id == session.id
                )
                scoped_source = next(
                    item for item in scoped.runs if item.id == source.id
                )
                setattr(scoped_source, attribute, value)
                candidate_audit, candidate_thread = (
                    orchestrator._build_continuity_audit(
                        scoped,
                        scoped_session,
                        identity=self.identity,
                        run_id="MR-hostile-next",
                        role=Role.CAPTAIN,
                        wave_kind=None,
                    )
                )
                self.assertEqual(
                    candidate_audit["decision"],
                    "fresh",
                )
                self.assertEqual(
                    candidate_audit["reason"],
                    expected_reason,
                )
                self.assertIsNone(candidate_thread)
                self.assertFalse(candidate_audit["stable_lane"])

        contract_stale = copy.deepcopy(scope_state)
        contract_session = next(
            item
            for item in contract_stale.sessions
            if item.id == session.id
        )
        contract_source = next(
            item
            for item in contract_stale.runs
            if item.id == source.id
        )
        contract_source.extra["contract_version"] = 1
        candidate_audit, candidate_thread = (
            orchestrator._build_continuity_audit(
                contract_stale,
                contract_session,
                identity=self.identity,
                run_id="MR-contract-next",
                role=Role.CAPTAIN,
                wave_kind=None,
            )
        )
        self.assertEqual(
            candidate_audit["reason"],
            "prior_contract_mismatch",
        )
        self.assertIsNone(candidate_thread)

        cross_role = copy.deepcopy(scope_state)
        cross_role_session = next(
            item
            for item in cross_role.sessions
            if item.id == session.id
        )
        for item in cross_role.runs:
            if (
                item.session_id == session.id
                and item.role == Role.CAPTAIN.value
            ):
                item.role = Role.BUILDER.value
        candidate_audit, candidate_thread = (
            orchestrator._build_continuity_audit(
                cross_role,
                cross_role_session,
                identity=self.identity,
                run_id="MR-role-next",
                role=Role.CAPTAIN,
                wave_kind=None,
            )
        )
        self.assertEqual(
            candidate_audit["reason"],
            "no_prior_lane_run",
        )
        self.assertIsNone(candidate_thread)

        source_run = next(
            item
            for item in state.runs
            if item.id == audit["source_run_id"]
        )
        secret_path = (
            engine.store.challenge_paths(self.identity).root
            / source_run.extra["thread_secret_path"]
        )
        secret = read_json(secret_path)
        secret["thread_id"] = "invalid thread with spaces"
        from ctf_os.store.atomic import atomic_write_json

        atomic_write_json(secret_path, secret)
        with self.assertRaisesRegex(ManagedError, "changed"):
            orchestrator._resume_thread_for_reserved_run(
                self.identity,
                captain.id,
            )

    def test_cli_defaults_fresh_and_routes_explicit_policy(self) -> None:
        parser = cli.build_parser()
        default = parser.parse_args(
            ["solve", "contest", "rev", "task", "--mode", "managed"]
        )
        self.assertEqual(default.thread_continuity, "fresh")
        explicit = parser.parse_args(
            [
                "solve",
                "contest",
                "rev",
                "task",
                "--mode",
                "managed",
                "--thread-continuity",
                "captain_lane",
            ]
        )
        self.assertEqual(explicit.thread_continuity, "captain_lane")

        engine = ChallengeEngine(self.root)
        engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        state = engine.store.load(self.identity)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                ManagedOrchestrator,
                "run_cycles",
                autospec=True,
                return_value=state,
            ) as run_cycles,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = cli.main(
                [
                    "solve",
                    self.identity.contest_id,
                    self.identity.category,
                    self.identity.challenge_id,
                    "--mode",
                    "managed",
                    "--thread-continuity=role_lane",
                    "--max-cycles=1",
                ],
                root=self.root,
            )
        self.assertEqual(status, 0, stderr.getvalue())
        self.assertEqual(
            run_cycles.call_args.kwargs["thread_continuity_policy"],
            "role_lane",
        )

        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = cli.main(
                [
                    "solve",
                    self.identity.contest_id,
                    self.identity.category,
                    self.identity.challenge_id,
                    "--mode",
                    "assisted",
                    "--thread-continuity=role_lane",
                ],
                root=self.root,
            )
        self.assertNotEqual(status, 0)
        self.assertIn("only in managed mode", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
