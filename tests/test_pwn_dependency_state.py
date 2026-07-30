from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

from ctf_os.engine.pwn_dependency_state import (
    PWN_DEPENDENCY_STATE_JOURNAL_KEY,
    PwnDependencyStateError,
    _proven_leak_for_snapshot,
    project_pwn_dependency_context,
    validate_pwn_dependency_state_graph,
    verify_pwn_dependency_artifact_bytes,
    verify_pwn_dependency_static_target,
)
from ctf_os.engine.pwn_leak import PwnLeakStatus
from ctf_os.engine.pwn_ip_control import (
    PwnIpControlReplayCommitment,
)
from ctf_os.models import ModelValidationError
from tests import test_pwn_exploit_effect_hotpath as effect_hotpath
from tests import test_pwn_leak_hotpath as leak_hotpath


def _canonical_sha256(value: object) -> str:
    payload = (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


class PwnDependencyStateTests(unittest.TestCase):
    def _fixture(self):
        lifecycle = effect_hotpath.PwnExploitEffectHotPathTests(
            methodName=(
                "test_preissued_six_replays_prove_narrow_effect_only"
            )
        )
        lifecycle.setUp()
        self.addCleanup(lifecycle.doCleanups)
        self.addCleanup(lifecycle.tearDown)
        fixture, engine, coordinator, parent_id = lifecycle._fixture()
        return lifecycle, fixture, engine, coordinator, parent_id

    @staticmethod
    def _complete(lifecycle, fixture, engine, parent_id):
        return engine.prove_pwn_exploit_effect(
            fixture.identity,
            parent_experiment_id=parent_id,
            payload_locator="exploit.bin",
            _session_owned=True,
        )

    def test_slots_replay_commitment_serializes_without_zero_arg_super(
        self,
    ) -> None:
        values = {
            "capability_attestation_artifact_id": "A-capability",
            "capability_attestation_sha256": "1" * 64,
            "evaluation_sha256": "2" * 64,
            "ordinal": 1,
            "payload_artifact_id": "A-payload",
            "payload_sha256": "3" * 64,
            "payload_size_bytes": 8,
            "receipt_sha256": "4" * 64,
            "recipe_sha256": "5" * 64,
            "stdout_artifact_id": "A-stdout",
            "stdout_artifact_sha256": "6" * 64,
            "stdout_artifact_size_bytes": 1,
            "target_value_sha256": "7" * 64,
        }
        commitment = PwnIpControlReplayCommitment.from_dict(values)
        self.assertEqual(commitment.to_dict(), values)

    def test_L_source_is_only_actual_three_replay_proven_leak(
        self,
    ) -> None:
        lifecycle = leak_hotpath.PwnLeakHotPathTests(
            methodName=(
                "test_temporal_preissue_and_three_replays_prove_only_leak"
            )
        )
        lifecycle.setUp()
        self.addCleanup(lifecycle.doCleanups)
        self.addCleanup(lifecycle.tearDown)
        (
            fixture,
            _coordinator,
            engine,
            _snapshot_state,
            snapshot_id,
            leak_id,
            _payload,
        ) = lifecycle._fixture()
        completed = engine.execute_registered_experiments(
            fixture.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(leak_id,),
        )
        experiment, result = _proven_leak_for_snapshot(
            completed,
            snapshot_id,
        )
        self.assertIsNotNone(experiment)
        self.assertIsNotNone(result)
        self.assertEqual(experiment.id, leak_id)
        self.assertIs(result.status, PwnLeakStatus.PROVEN)
        self.assertEqual(len(result.replays), 3)
        self.assertEqual(
            [
                completed.runs[
                    next(
                        index
                        for index, run in enumerate(completed.runs)
                        if run.id == run_id
                    )
                ].extra["pwn_leak_replay"]["receipt"]["receipt_id"]
                for run_id in experiment.evidence_run_ids
            ],
            experiment.extra["receipt_ids"],
        )

    def test_no_leak_chain_is_exact_raw_free_and_descriptor_revalidated(
        self,
    ) -> None:
        lifecycle, fixture, engine, _coordinator, parent_id = (
            self._fixture()
        )
        final, result = self._complete(
            lifecycle,
            fixture,
            engine,
            parent_id,
        )
        validate_pwn_dependency_state_graph(final)
        root = final.extra[PWN_DEPENDENCY_STATE_JOURNAL_KEY]
        self.assertEqual(len(root), 1)
        graph_id, wrapper = next(iter(root.items()))
        graph = wrapper["graph"]
        self.assertEqual(
            graph["branch"],
            "DEPENDENCY_SCOPED_NOT_APPLICABLE",
        )
        self.assertEqual(
            graph["gate_route"],
            ["D", "V", "N/A", "P", "E"],
        )
        address = graph["nodes"]["address_resolution"]
        self.assertFalse(address["advisory_authority_used"])
        self.assertFalse(address["non_pie_inference_used"])
        self.assertEqual(
            address["decision_phase"],
            "retrospective_after_exact_effect",
        )
        self.assertEqual(address["leak_dependency_ids"], [])
        self.assertEqual(
            {
                (edge["from"], edge["to"])
                for edge in graph["evidence_edges"]
            },
            {("P", "N/A"), ("E", "N/A")},
        )
        context = project_pwn_dependency_context(
            final,
            graph_id=graph_id,
        )
        self.assertEqual(context["status"], "COMPLETE")
        self.assertFalse(context["raw_output_included"])
        self.assertIn("state.json#/extra/", context["graph_pointer"])
        paths = engine.store.challenge_paths(fixture.identity)
        artifact_report = verify_pwn_dependency_artifact_bytes(
            paths.root,
            final,
            graph_id=graph_id,
        )
        self.assertGreater(artifact_report["artifact_count"], 50)
        self.assertTrue(artifact_report["descriptor_reread"])
        self.assertTrue(artifact_report["nofollow_required"])
        self.assertFalse(artifact_report["raw_output_returned"])
        source_report = verify_pwn_dependency_static_target(
            engine.challenge_input(fixture.identity),
            final,
            graph_id=graph_id,
        )
        self.assertFalse(source_report["raw_output_returned"])
        self.assertEqual(
            source_report["source_sha256"],
            graph["static_target"]["source_sha256"],
        )
        validated_query = engine.validate_pwn_dependency_graph(
            fixture.identity,
            graph_id=graph_id,
        )
        self.assertTrue(validated_query["ok"])
        self.assertTrue(validated_query["primitive_recomputed"])
        self.assertFalse(validated_query["raw_output_returned"])
        self.assertEqual(
            engine.query_pwn_dependency_graph(
                fixture.identity,
                graph_id=graph_id,
            )["graph_sha256"],
            wrapper["graph_sha256"],
        )
        self.assertTrue(result.exploit_effect_proven)
        self.assertEqual(final.candidates, [])
        self.assertEqual(final.submissions, [])

        first_artifact = graph["support_closure"]["artifacts"][0]
        artifact_path = paths.root / first_artifact["path"]
        backup_path = Path(str(artifact_path) + ".descriptor-backup")
        artifact_path.rename(backup_path)
        artifact_path.symlink_to(backup_path.name)
        with self.assertRaises(PwnDependencyStateError):
            engine.query_pwn_dependency_graph(
                fixture.identity,
                graph_id=graph_id,
            )

    def test_rehashed_tamper_stale_advisory_and_loose_marker_reject(
        self,
    ) -> None:
        lifecycle, fixture, engine, _coordinator, parent_id = (
            self._fixture()
        )
        final, _result = self._complete(
            lifecycle,
            fixture,
            engine,
            parent_id,
        )
        graph_id = next(
            iter(final.extra[PWN_DEPENDENCY_STATE_JOURNAL_KEY])
        )

        def mutate_graph(callback):
            state = copy.deepcopy(final)
            wrapper = state.extra[
                PWN_DEPENDENCY_STATE_JOURNAL_KEY
            ][graph_id]
            callback(wrapper["graph"])
            wrapper["graph_sha256"] = _canonical_sha256(
                wrapper["graph"]
            )
            return state

        attacks = {
            "dependency-edge": lambda graph: graph["gate_edges"][
                1
            ].__setitem__("to", "E"),
            "stale-revision": lambda graph: (
                graph.__setitem__(
                    "source_state_revision",
                    graph["source_state_revision"] + 1,
                ),
                graph.__setitem__(
                    "committed_state_revision",
                    graph["committed_state_revision"] + 1,
                ),
            ),
            "advisory-authority": lambda graph: graph[
                "advisory"
            ].__setitem__("authority_used", True),
            "non-pie-inference": lambda graph: graph["nodes"][
                "address_resolution"
            ].__setitem__("non_pie_inference_used", True),
            "upstream-artifact": lambda graph: graph[
                "support_closure"
            ]["artifacts"][0].__setitem__("sha256", "0" * 64),
        }
        for name, callback in attacks.items():
            with self.subTest(name=name):
                attacked = mutate_graph(callback)
                with self.assertRaises(PwnDependencyStateError):
                    validate_pwn_dependency_state_graph(
                        attacked
                    )
                with self.assertRaises(ModelValidationError):
                    attacked.validate()

        missing = copy.deepcopy(final)
        missing.extra.pop(PWN_DEPENDENCY_STATE_JOURNAL_KEY)
        with self.assertRaises(PwnDependencyStateError):
            validate_pwn_dependency_state_graph(missing)
        with self.assertRaises(ModelValidationError):
            missing.validate()

        loose = copy.deepcopy(final)
        loose.extra[PWN_DEPENDENCY_STATE_JOURNAL_KEY] = {
            graph_id: {
                "status": "PROVEN",
                "marker": "pwn_dependency_graph_v1",
            }
        }
        with self.assertRaises(PwnDependencyStateError):
            validate_pwn_dependency_state_graph(loose)

    def test_interruption_retains_preissue_without_dependency_authority(
        self,
    ) -> None:
        _lifecycle, fixture, engine, coordinator, parent_id = (
            self._fixture()
        )
        coordinator.fail_on_call = 2
        with self.assertRaisesRegex(
            RuntimeError,
            "synthetic exploit-effect interruption",
        ):
            engine.prove_pwn_exploit_effect(
                fixture.identity,
                parent_experiment_id=parent_id,
                payload_locator="exploit.bin",
                _session_owned=True,
            )
        state = engine.store.load(fixture.identity, recover=False)
        self.assertNotIn(
            PWN_DEPENDENCY_STATE_JOURNAL_KEY,
            state.extra,
        )
        context = project_pwn_dependency_context(state)
        self.assertEqual(context["status"], "INCOMPLETE")
        self.assertEqual(context["current_gate"], "E")
        self.assertIn(
            "effect_preissued_not_final",
            context["failure_codes"],
        )
        self.assertFalse(context["raw_output_included"])
        self.assertEqual(state.candidates, [])
        self.assertEqual(state.submissions, [])


if __name__ == "__main__":
    unittest.main()
