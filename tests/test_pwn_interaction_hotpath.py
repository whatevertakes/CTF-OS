from __future__ import annotations

import hashlib
import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from ctf_os import cli
from ctf_os.capabilities import REQUIRED_MANAGED_ATTESTATIONS
from ctf_os.engine.pwn_interaction import (
    PwnInteractionExpectedBinding,
)
from ctf_os.engine.pwn_interaction_hotpath import (
    PWN_INTERACTION_ENGINE_EXECUTOR,
    PWN_INTERACTION_PRODUCER_SHA256,
    PWN_INTERACTION_STATE_KEY,
    PwnInteractionHotPathError,
)
from ctf_os.engine.pwn_ip_control import (
    pwn_ip_control_child_experiment_id,
)
from ctf_os.engine.pwn_runtime_snapshot import (
    pwn_runtime_snapshot_child_experiment_id,
)
from ctf_os.models import ExperimentStatus, RunStatus
from ctf_os.sandbox import ArtifactRef, SandboxResult
from ctf_os.store import StateStore
from ctf_os.store.atomic import atomic_write_json, read_json
from tests import test_pwn_crash_execution as crash_execution
from tests import test_pwn_interaction_evaluation as evaluation_fixture
from tests import test_pwn_ip_control_lifecycle as ip_lifecycle


_RELEASE_SCRIPT = (
    Path(__file__).resolve().parent.parent
    / "scripts"
    / "check-pwn-interaction-hotpath-docker.py"
)
_RELEASE_SPEC = importlib.util.spec_from_file_location(
    "ctfos_pwn_interaction_hotpath_release",
    _RELEASE_SCRIPT,
)
if _RELEASE_SPEC is None or _RELEASE_SPEC.loader is None:
    raise RuntimeError("could not load Pwn interaction release proof")
interaction_release = importlib.util.module_from_spec(_RELEASE_SPEC)
_RELEASE_SPEC.loader.exec_module(interaction_release)


class _InteractionSandbox:
    def __init__(self, owner, work: Path) -> None:
        self.owner = owner
        self.work = work

    @property
    def scope_fingerprint(self) -> str:
        if self.owner.vary_scope_call == self.owner.calls:
            return "8" * 64
        return "7" * 64

    def initialize_workspace(self, *, deadline_monotonic_seconds=None):
        del deadline_monotonic_seconds

    def register_artifact(self, locator, *, maximum_bytes=1 << 34):
        path = self.work / locator
        payload = path.read_bytes()
        if len(payload) > maximum_bytes:
            raise ValueError("fake artifact bound exceeded")
        return ArtifactRef(
            locator=locator,
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
            scope_fingerprint=self.scope_fingerprint,
        )

    def run_clean_proof(
        self,
        spec,
        *,
        input_locators=(),
        proof_inputs=(),
        proof_outputs=(),
    ):
        if input_locators or len(proof_inputs) != 1:
            raise AssertionError("one typed recipe input required")
        self.owner.calls += 1
        call = self.owner.calls
        self.owner.observe_preissue()
        if (
            self.owner.tamper_prior_evidence_call == call
            and call > 1
        ):
            state = self.owner.engine.store.load(self.owner.identity)
            attempt = next(
                iter(state.extra[PWN_INTERACTION_STATE_KEY].values())
            )
            if self.owner.tamper_prior_kind == "result":
                first_run_id = attempt["replays"][0]["run_id"]
                target = self.owner.engine.store.run_paths(
                    self.owner.identity,
                    first_run_id,
                ).result
            elif self.owner.tamper_prior_kind == "capture":
                capture_root = (
                    self.owner.engine.store.challenge_paths(
                        self.owner.identity
                    ).artifacts
                    / "pwn-interaction"
                    / attempt["attempt_id"]
                    / "captures"
                )
                target = sorted(capture_root.iterdir())[0]
            else:
                raise AssertionError("invalid prior evidence defect")
            target.chmod(0o600)
            target.write_bytes(b"tampered prior evidence\n")
        if self.owner.fail_on_call == call:
            raise RuntimeError("synthetic partial interaction failure")
        argv = spec.argv
        phase = crash_execution._argument(argv, "--phase")
        ordinal = int(
            crash_execution._argument(argv, "--ordinal")
        )
        recipe_path = (
            self.work / proof_inputs[0].source_locator
        )
        recipe = recipe_path.read_bytes()
        binding = PwnInteractionExpectedBinding(
            configuration_epoch=int(
                crash_execution._argument(
                    argv,
                    "--configuration-epoch",
                )
            ),
            image_digest=crash_execution._argument(
                argv, "--image-digest"
            ),
            preissue_sha256=crash_execution._argument(
                argv, "--preissue-sha256"
            ),
            producer_sha256=PWN_INTERACTION_PRODUCER_SHA256,
            recipe_sha256=hashlib.sha256(recipe).hexdigest(),
            recipe_size_bytes=len(recipe),
            source_manifest_sha256=crash_execution._argument(
                argv, "--source-manifest-sha256"
            ),
            source_sha256=crash_execution._argument(
                argv, "--source-sha256"
            ),
            source_size_bytes=int(
                crash_execution._argument(
                    argv, "--source-size-bytes"
                )
            ),
        )
        evidence = evaluation_fixture._make_replay(
            binding,
            phase,
            ordinal,
        )
        if self.owner.invalid_document_call == call:
            evidence = type(evidence)(
                document_bytes=b"{}\n",
                stdout_bytes=evidence.stdout_bytes,
                stderr_bytes=evidence.stderr_bytes,
                transcript_bytes=evidence.transcript_bytes,
                derivation_dag_bytes=evidence.derivation_dag_bytes,
            )
        clean_index = (
            1
            if self.owner.reuse_proof_identity_call == call
            else call
        )
        clean = Path("proof") / f"clean-{clean_index:012x}"
        directory = self.work / clean
        outputs = directory / "outputs"
        outputs.mkdir(parents=True, exist_ok=True)
        (directory / "stdout.log").write_bytes(
            evidence.document_bytes
        )
        (directory / "stderr.log").write_bytes(b"")
        raw_outputs = (
            evidence.stdout_bytes,
            evidence.stderr_bytes,
            evidence.transcript_bytes,
            evidence.derivation_dag_bytes,
        )
        output_refs = []
        for output_index, (declaration, payload) in enumerate(zip(
            proof_outputs,
            raw_outputs,
            strict=True,
        )):
            (outputs / declaration.name).write_bytes(payload)
            locator = (
                clean / "outputs" / declaration.name
            ).as_posix()
            if (
                self.owner.wrong_output_prefix_call == call
                and output_index == 0
            ):
                locator = (
                    Path("proof")
                    / "clean-deadbeefdead"
                    / "outputs"
                    / declaration.name
                ).as_posix()
            output_refs.append(
                ArtifactRef(
                    locator=locator,
                    sha256=hashlib.sha256(payload).hexdigest(),
                    size_bytes=len(payload),
                    scope_fingerprint=self.scope_fingerprint,
                )
            )
        if self.owner.tamper_after_call == call:
            state = self.owner.engine.store.load(
                self.owner.identity
            )
            attempt = next(
                iter(state.extra[PWN_INTERACTION_STATE_KEY].values())
            )
            artifact = next(
                item
                for item in state.artifacts
                if item.id == attempt["preissue_artifact_id"]
            )
            target = (
                self.owner.engine.store.challenge_paths(
                    self.owner.identity
                ).root
                / artifact.path
            )
            target.chmod(0o600)
            target.write_bytes(b"tampered\n")
        return SandboxResult(
            # The production clean workspace starts its local sequence at one
            # each time.  Physical identity therefore includes scope and the
            # durable clean prefix rather than treating this bare ID as
            # globally unique.
            run_id="run-00000001",
            status="completed",
            exit_code=0,
            timed_out=False,
            duration_ms=4,
            stdout_summary=evidence.document_bytes.decode("ascii"),
            stderr_summary="",
            stdout_bytes=len(evidence.document_bytes),
            stderr_bytes=0,
            stdout_path=f"/work/{clean.as_posix()}/stdout.log",
            stderr_path=f"/work/{clean.as_posix()}/stderr.log",
            stdout_stored_bytes=len(evidence.document_bytes),
            stderr_stored_bytes=0,
            stdout_limit_bytes=1024 * 1024,
            stderr_limit_bytes=1024 * 1024,
            stdout_truncated=False,
            stderr_truncated=False,
            stdout_truncation_known=True,
            stderr_truncation_known=True,
            stdout_capture_complete=True,
            stderr_capture_complete=True,
            stdout_summary_truncated=False,
            stderr_summary_truncated=False,
            stdout_error=None,
            stderr_error=None,
            stream_capture_error=None,
            orchestration_error=None,
            proof_outputs=tuple(output_refs),
        )

    def run(self, spec):
        raise AssertionError(f"unexpected normal sandbox run: {spec}")

    def start_job(self, *args, **kwargs):
        raise AssertionError("not used")

    def job_status(self, *args, **kwargs):
        raise AssertionError("not used")

    def job_log(self, *args, **kwargs):
        raise AssertionError("not used")

    def cancel_job(self, *args, **kwargs):
        raise AssertionError("not used")


class _Coordinator:
    def __init__(self, engine, identity) -> None:
        self.engine = engine
        self.identity = identity
        self.calls = 0
        self.fail_on_call: int | None = None
        self.invalid_document_call: int | None = None
        self.reuse_proof_identity_call: int | None = None
        self.tamper_after_call: int | None = None
        self.tamper_prior_evidence_call: int | None = None
        self.tamper_prior_kind: str | None = None
        self.vary_scope_call: int | None = None
        self.wrong_output_prefix_call: int | None = None
        self.preissue_snapshots: list[tuple[int, int, str]] = []
        self.sandboxes: list[_InteractionSandbox] = []

    def factory(self, _state, work, policy):
        self.assert_network_none(policy)
        sandbox = _InteractionSandbox(self, work)
        self.sandboxes.append(sandbox)
        return sandbox

    @staticmethod
    def assert_network_none(policy) -> None:
        if policy.allow_targets or policy.docker_network != "none":
            raise AssertionError("interaction proof is not network-none")

    def observe_preissue(self) -> None:
        state = self.engine.store.load(self.identity)
        attempts = state.extra[PWN_INTERACTION_STATE_KEY]
        attempt = next(iter(attempts.values()))
        runs = [
            next(item for item in state.runs if item.id == run_id)
            for run_id in (
                replay["run_id"] for replay in attempt["replays"]
            )
        ]
        self.preissue_snapshots.append(
            (
                len(runs),
                sum(
                    item.status is RunStatus.CREATED
                    for item in runs
                ),
                attempt["status"],
            )
        )


class PwnInteractionHotPathTests(unittest.TestCase):
    def test_failed_ip_parent_reason_is_bounded_and_terminal_safe(self):
        parent = SimpleNamespace(
            id="E-ip-control",
            status=ExperimentStatus.FAILED,
            result={"error": "sentinel\n" + ("x" * 2_000)},
        )
        state = SimpleNamespace(experiments=[parent])
        with self.assertRaises(AssertionError) as raised:
            interaction_release._typed_parent(state, parent.id)
        message = str(raised.exception)
        self.assertIn("status=failed", message)
        self.assertIn(r"error=sentinel\x0a", message)
        self.assertNotIn("\n", message)
        self.assertLess(len(message), 700)

    def _fixture(self):
        lifecycle = ip_lifecycle.PwnIpControlLifecycleTests(
            methodName=(
                "test_confirmed_snapshot_proves_only_ip_control_in_three_replays"
            )
        )
        lifecycle.setUp()
        self.addCleanup(lifecycle.doCleanups)
        self.addCleanup(lifecycle.tearDown)
        fixture, _old_coordinator, engine, parent_id, _payload = (
            lifecycle._fixture()
        )
        fixture._execute(engine, parent_id)
        snapshot_id = pwn_runtime_snapshot_child_experiment_id(
            parent_id
        )
        engine._capability_probe = lifecycle._snapshot_capability
        engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(snapshot_id,),
        )
        ip_control_id = pwn_ip_control_child_experiment_id(
            snapshot_id
        )
        engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(ip_control_id,),
        )

        def capability(digest):
            return {
                "attestation_errors": {},
                "attestations": {
                    "pwn_interaction_v1": dict(
                        REQUIRED_MANAGED_ATTESTATIONS[
                            "pwn_interaction_v1"
                        ]
                    )
                },
                "available": ["pwn_interaction_v1"],
                "image_digest": digest,
                "ok": True,
            }

        engine._capability_probe = capability
        state = engine.store.load(fixture.identity)
        workspace = engine._workspace(state)
        (workspace / "interaction.json").write_bytes(
            evaluation_fixture._recipe()
        )
        coordinator = _Coordinator(engine, fixture.identity)
        engine._sandbox_factory = coordinator.factory
        return fixture, engine, coordinator, ip_control_id

    def test_success_preissues_six_and_adds_only_narrow_fact_progress(self):
        fixture, engine, coordinator, parent_id = self._fixture()
        before = engine.store.load(fixture.identity)
        before_shape = (
            before.status,
            len(before.candidates),
            len(before.submissions),
            len(before.facts),
            len(before.progress_markers),
        )
        final, evaluation = engine.prove_pwn_interaction(
            fixture.identity,
            parent_experiment_id=parent_id,
            recipe_locator="interaction.json",
            _session_owned=True,
        )
        self.assertTrue(evaluation.passed)
        self.assertEqual(coordinator.calls, 6)
        self.assertEqual(
            coordinator.preissue_snapshots,
            [(6, 6, "preissued")] * 6,
        )
        self.assertEqual(
            (
                final.status,
                len(final.candidates),
                len(final.submissions),
            ),
            before_shape[:3],
        )
        self.assertEqual(len(final.facts), before_shape[3] + 1)
        self.assertEqual(
            len(final.progress_markers),
            before_shape[4] + 1,
        )
        child = next(
            item
            for item in final.experiments
            if item.extra.get("engine_executor")
            == PWN_INTERACTION_ENGINE_EXECUTOR
        )
        self.assertIs(child.status, ExperimentStatus.COMPLETED)
        self.assertEqual(len(child.evidence_run_ids), 6)
        self.assertEqual(len(child.evidence_receipt_ids), 6)
        attempt = next(
            iter(final.extra[PWN_INTERACTION_STATE_KEY].values())
        )
        self.assertTrue(attempt["terminal"])
        self.assertEqual(attempt["status"], "passed")
        self.assertFalse(attempt["candidate_authorized"])
        self.assertFalse(
            attempt["automatic_submission_authorized"]
        )
        self.assertEqual(attempt["unique_proof_identity_count"], 6)
        self.assertEqual(attempt["unique_clean_prefix_count"], 6)
        self.assertEqual(
            attempt["canonical_scope_fingerprint"],
            "7" * 64,
        )
        self.assertEqual(
            len(
                {
                    (
                        item["scope_fingerprint"],
                        item["sandbox_run_id"],
                        item["clean_prefix"],
                    )
                    for item in attempt["proof_identities"]
                }
            ),
            6,
        )
        for run_id in child.evidence_run_ids:
            run = next(item for item in final.runs if item.id == run_id)
            run_paths = engine.store.run_paths(fixture.identity, run_id)
            result_document = __import__("json").loads(
                run_paths.result.read_text(encoding="utf-8")
            )
            validation_document = __import__("json").loads(
                run_paths.validation.read_text(encoding="utf-8")
            )
            persisted = run.extra["pwn_interaction"]["transport"][
                "proof_identity"
            ]
            self.assertEqual(
                result_document["transport"]["proof_identity"],
                persisted,
            )
            self.assertEqual(
                validation_document["transport"]["proof_identity"],
                persisted,
            )
        final.validate()
        physical = interaction_release._interaction_physical_summary(
            final,
            engine.store,
            fixture.identity,
            attempt,
        )
        self.assertEqual(physical["fresh_clean_workspaces"], 6)
        self.assertEqual(physical["network_none"], 6)
        self.assertEqual(physical["one_shot"], 6)
        self.assertEqual(physical["proof_outputs_per_run"], 4)
        self.assertEqual(len(physical["physical_records"]), 6)

        hostile_run = engine.store.run_paths(
            fixture.identity,
            child.evidence_run_ids[0],
        )
        hostile_validation = read_json(hostile_run.validation)
        hostile_validation["transport"]["network"] = "bridge"
        atomic_write_json(
            hostile_run.validation,
            hostile_validation,
            mode=0o400,
        )
        with self.assertRaisesRegex(
            AssertionError,
            "physical sidecars disagree",
        ):
            interaction_release._interaction_physical_summary(
                final,
                engine.store,
                fixture.identity,
                attempt,
            )

    def test_preissue_commit_failure_removes_attempt_tree_and_runs(self):
        fixture, engine, _coordinator, parent_id = self._fixture()
        paths = engine.store.challenge_paths(fixture.identity)
        attempt_family = paths.artifacts / "pwn-interaction"

        def files_below(root: Path) -> set[str]:
            if not root.exists():
                return set()
            return {
                path.relative_to(root).as_posix()
                for path in root.rglob("*")
                if path.is_file()
            }

        before_files = files_below(attempt_family)
        before_runs = {path.name for path in paths.runs.iterdir()}
        original_update = engine.store.update

        def reject_preissue(*args, **kwargs):
            apply = args[1]
            if getattr(apply, "__name__", "") == "commit_preissue":
                raise RuntimeError("synthetic preissue commit failure")
            return original_update(*args, **kwargs)

        with (
            mock.patch.object(
                engine.store,
                "update",
                side_effect=reject_preissue,
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "synthetic preissue commit failure",
            ),
        ):
            engine.prove_pwn_interaction(
                fixture.identity,
                parent_experiment_id=parent_id,
                recipe_locator="interaction.json",
                _session_owned=True,
            )

        self.assertEqual(files_below(attempt_family), before_files)
        self.assertEqual(
            {path.name for path in paths.runs.iterdir()},
            before_runs,
        )
        self.assertNotIn(
            PWN_INTERACTION_STATE_KEY,
            engine.store.load(fixture.identity).extra,
        )

    def test_partial_failure_terminalizes_full_matrix_without_authority(self):
        fixture, engine, coordinator, parent_id = self._fixture()
        coordinator.fail_on_call = 2
        before = engine.store.load(fixture.identity)
        with self.assertRaisesRegex(
            RuntimeError,
            "synthetic partial interaction failure",
        ):
            engine.prove_pwn_interaction(
                fixture.identity,
                parent_experiment_id=parent_id,
                recipe_locator="interaction.json",
                _session_owned=True,
            )
        state = engine.store.load(fixture.identity)
        attempt = next(
            iter(state.extra[PWN_INTERACTION_STATE_KEY].values())
        )
        self.assertEqual(attempt["status"], "failed")
        self.assertTrue(attempt["terminal"])
        self.assertEqual(attempt["completed_replays"], 1)
        self.assertEqual(len(state.facts), len(before.facts))
        self.assertEqual(
            len(state.progress_markers),
            len(before.progress_markers),
        )
        self.assertEqual(len(state.candidates), len(before.candidates))
        self.assertEqual(
            len(state.submissions), len(before.submissions)
        )
        run_ids = [item["run_id"] for item in attempt["replays"]]
        run_statuses = [
            next(run for run in state.runs if run.id == run_id).status
            for run_id in run_ids
        ]
        self.assertEqual(run_statuses[0], RunStatus.COMPLETED)
        self.assertTrue(
            all(
                status is RunStatus.INTERRUPTED
                for status in run_statuses[1:]
            )
        )
        self.assertEqual(
            len(
                [
                    item
                    for item in state.receipts
                    if item.id
                    in {
                        replay["receipt_id"]
                        for replay in attempt["replays"]
                    }
                ]
            ),
            6,
        )
        state.validate()

    def test_preissue_tamper_fails_before_second_replay_and_no_authority(self):
        fixture, engine, coordinator, parent_id = self._fixture()
        coordinator.tamper_after_call = 1
        before = engine.store.load(fixture.identity)
        with self.assertRaisesRegex(
            PwnInteractionHotPathError,
            "preissue_artifact_changed",
        ):
            engine.prove_pwn_interaction(
                fixture.identity,
                parent_experiment_id=parent_id,
                recipe_locator="interaction.json",
                _session_owned=True,
            )
        self.assertEqual(coordinator.calls, 1)
        state = engine.store.load(fixture.identity)
        attempt = next(
            iter(state.extra[PWN_INTERACTION_STATE_KEY].values())
        )
        self.assertTrue(attempt["terminal"])
        self.assertEqual(attempt["status"], "failed")
        self.assertEqual(len(state.facts), len(before.facts))
        self.assertEqual(
            len(state.progress_markers),
            len(before.progress_markers),
        )
        self.assertEqual(len(state.submissions), len(before.submissions))
        replay_run_ids = {
            item["run_id"] for item in attempt["replays"]
        }
        replay_receipt_ids = {
            item["receipt_id"] for item in attempt["replays"]
        }
        self.assertTrue(
            all(
                item.status
                in {RunStatus.COMPLETED, RunStatus.INTERRUPTED}
                for item in state.runs
                if item.id in replay_run_ids
            )
        )
        self.assertEqual(
            {
                item.id
                for item in state.receipts
                if item.id in replay_receipt_ids
            },
            replay_receipt_ids,
        )
        reopened = StateStore(
            engine.store.workspace_root,
            max_artifact_bytes=engine.store.max_artifact_bytes,
        ).load(fixture.identity, recover=False)
        self.assertEqual(reopened.revision, state.revision)
        state.validate()

    def test_evaluator_rejection_is_terminal_and_never_promotes(self):
        fixture, engine, coordinator, parent_id = self._fixture()
        coordinator.invalid_document_call = 4
        before = engine.store.load(fixture.identity)
        with self.assertRaisesRegex(
            PwnInteractionHotPathError,
            "evaluation_rejected",
        ):
            engine.prove_pwn_interaction(
                fixture.identity,
                parent_experiment_id=parent_id,
                recipe_locator="interaction.json",
                _session_owned=True,
            )
        self.assertEqual(coordinator.calls, 6)
        state = engine.store.load(fixture.identity)
        attempt = next(
            iter(state.extra[PWN_INTERACTION_STATE_KEY].values())
        )
        self.assertTrue(attempt["terminal"])
        self.assertEqual(attempt["status"], "failed")
        aggregate = next(
            item
            for item in state.experiments
            if item.id == attempt["experiment_id"]
        )
        self.assertIs(aggregate.status, ExperimentStatus.FAILED)
        self.assertEqual(len(state.facts), len(before.facts))
        self.assertEqual(
            len(state.progress_markers),
            len(before.progress_markers),
        )
        self.assertEqual(len(state.candidates), len(before.candidates))
        self.assertEqual(
            len(state.submissions), len(before.submissions)
        )
        state.validate()

    def test_cross_clean_output_and_reused_physical_identity_fail_closed(self):
        for defect in (
            "wrong_prefix",
            "reused_identity",
            "reused_prefix_changed_scope",
        ):
            with self.subTest(defect=defect):
                fixture, engine, coordinator, parent_id = self._fixture()
                if defect == "wrong_prefix":
                    coordinator.wrong_output_prefix_call = 1
                else:
                    coordinator.reuse_proof_identity_call = 2
                    if defect == "reused_prefix_changed_scope":
                        coordinator.vary_scope_call = 2
                with self.assertRaisesRegex(
                    PwnInteractionHotPathError,
                    "(?:scope|output)_binding_invalid",
                ):
                    engine.prove_pwn_interaction(
                        fixture.identity,
                        parent_experiment_id=parent_id,
                        recipe_locator="interaction.json",
                        _session_owned=True,
                    )
                state = engine.store.load(fixture.identity)
                attempt = next(
                    iter(
                        state.extra[
                            PWN_INTERACTION_STATE_KEY
                        ].values()
                    )
                )
                self.assertTrue(attempt["terminal"])
                self.assertEqual(attempt["status"], "failed")
                self.assertFalse(
                    any(
                        item.id == attempt["fact_id"]
                        for item in state.facts
                    )
                )
                state.validate()

    def test_completed_sidecar_or_capture_tamper_restores_then_terminalizes(self):
        for kind in ("result", "capture"):
            with self.subTest(kind=kind):
                fixture, engine, coordinator, parent_id = self._fixture()
                coordinator.tamper_prior_evidence_call = 2
                coordinator.tamper_prior_kind = kind
                before = engine.store.load(fixture.identity)
                with self.assertRaisesRegex(
                    PwnInteractionHotPathError,
                    "completed_evidence_changed",
                ):
                    engine.prove_pwn_interaction(
                        fixture.identity,
                        parent_experiment_id=parent_id,
                        recipe_locator="interaction.json",
                        _session_owned=True,
                    )
                state = engine.store.load(
                    fixture.identity,
                    recover=False,
                )
                attempt = next(
                    iter(
                        state.extra[
                            PWN_INTERACTION_STATE_KEY
                        ].values()
                    )
                )
                self.assertEqual(attempt["status"], "failed")
                self.assertTrue(attempt["terminal"])
                self.assertEqual(
                    attempt["reason_code"],
                    "pwn_interaction_completed_evidence_changed",
                )
                self.assertEqual(len(state.facts), len(before.facts))
                self.assertEqual(
                    len(state.progress_markers),
                    len(before.progress_markers),
                )
                reopened = StateStore(
                    engine.store.workspace_root,
                    max_artifact_bytes=(
                        engine.store.max_artifact_bytes
                    ),
                ).load(fixture.identity, recover=False)
                self.assertEqual(reopened.revision, state.revision)

    def test_cli_is_one_explicit_challenge_parent_and_recipe(self):
        parsed = cli.build_parser().parse_args(
            [
                "pwn-prove-interaction",
                "Contest",
                "pwn",
                "Challenge",
                "--parent",
                "E-executed-parent",
                "--recipe",
                "zone-interaction.json",
                "--timeout",
                "600",
            ]
        )
        self.assertEqual(parsed.command, "pwn-prove-interaction")
        self.assertEqual(parsed.parent, "E-executed-parent")
        self.assertEqual(parsed.recipe, "zone-interaction.json")
        self.assertEqual(parsed.timeout, 600)


if __name__ == "__main__":
    unittest.main()
