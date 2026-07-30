from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

import ctf_os.engine.forensic_assertion_hotpath as hotpath
from ctf_os.engine.forensic_assertion_execution import (
    FORENSIC_ASSERTION_EXECUTION_PROTOCOL,
    FORENSIC_ASSERTION_OPERATOR_SPEC_PROTOCOL,
    ForensicToolReadiness,
    forensic_tool_readiness_registry_sha256,
)
from ctf_os.engine.forensic_assertion_graph import (
    FORENSIC_ASSERTION_MIN_COVERAGE_PPM,
    ForensicAssertionNode,
    ForensicAssertionState,
    ForensicFileRangePointer,
    build_forensic_assertion_graph_plan,
)
from ctf_os.engine.forensic_assertion_hotpath import (
    FORENSIC_ASSERTION_HOTPATH_PROTOCOL,
    FORENSIC_ASSERTION_READINESS_PROTOCOL,
    ForensicAssertionHotPathError,
    execute_forensic_assertion_hotpath,
)
from ctf_os.models import (
    ArtifactReference,
    RunStatus,
)
from ctf_os.sandbox import ArtifactRef, SandboxResult
from tests import test_forensic_hotpath as index_support


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


class _AssertionCoordinator:
    def __init__(self) -> None:
        self.engine = None
        self.identity = None
        self.policies = []
        self.command_specs = []
        self.pre_run_states: list[dict[str, object]] = []
        self.interrupt_ordinal: int | None = None
        self.corrupt_observation_ordinal: int | None = None
        self.mutate_source_ordinal: int | None = None
        self.cherry_pick_request_ordinal: int | None = None
        self.mutate_durable_output_on_observation = False
        self.run_count = 0

    def factory(self, state, work, policy):
        del state
        self.policies.append(policy)
        return _AssertionSandbox(work, self)

    def observe_preissue(self, request: dict[str, object]) -> None:
        assert self.engine is not None and self.identity is not None
        state = self.engine.store.load(self.identity, recover=False)
        attempts = state.extra["forensic_assertion_preissues"]
        attempt = next(reversed(attempts.values()))
        request_states = attempt["requests"]
        self.pre_run_states.append(
            {
                "all_request_files": all(
                    (
                        self.engine.store.challenge_paths(
                            self.identity
                        ).root
                        / item["request"]["path"]
                    ).is_file()
                    for item in request_states
                ),
                "all_runs_preissued": all(
                    any(run.id == item["run_id"] for run in state.runs)
                    for item in request_states
                ),
                "request_count": len(request_states),
                "statuses": [
                    item["status"] for item in request_states
                ],
                "tool_id": request["tool"]["tool_id"],
            }
        )


class _AssertionSandbox:
    scope_fingerprint = "a" * 64

    def __init__(
        self,
        work: Path,
        owner: _AssertionCoordinator,
    ) -> None:
        self.work = work
        self.owner = owner

    def initialize_workspace(self, *, deadline_monotonic_seconds=None):
        del deadline_monotonic_seconds

    def run(self, spec):
        self.owner.run_count += 1
        ordinal = self.owner.run_count
        self.owner.command_specs.append(spec)
        request_locator = spec.argv[
            spec.argv.index("--request") + 1
        ]
        request_payload = (self.work / request_locator).read_bytes()
        request = json.loads(request_payload)
        self.owner.observe_preissue(request)
        if self.owner.interrupt_ordinal == ordinal:
            raise KeyboardInterrupt(
                "synthetic Forensic assertion interruption"
            )
        artifact_path = self.work / request["artifact"]["path"]
        observation_path = (
            self.work / request["observation"]["path"]
        )
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        observation_path.parent.mkdir(parents=True, exist_ok=True)
        raw = (
            b"forensic-observation:"
            + request["pointer"]["pointer_id"].encode("ascii")
            + b":"
            + request["tool"]["tool_id"].encode("ascii")
        )
        artifact_path.write_bytes(raw)
        artifact_sha256 = _sha256(raw)
        if self.owner.corrupt_observation_ordinal == ordinal:
            artifact_sha256 = "0" * 64
        document = {
            "artifact": {
                "artifact_id": request["artifact"]["artifact_id"],
                "path": request["artifact"]["path"],
                "sha256": artifact_sha256,
                "size_bytes": len(raw),
            },
            "capture": {
                "capture_complete": True,
                "capture_error_code": None,
                "truncated": False,
                "truncation_known": True,
            },
            "command_argv_sha256": request["command"][
                "argv_sha256"
            ],
            "command_template_sha256": request["command"][
                "template_sha256"
            ],
            "execution_nonce_sha256": request[
                "execution_nonce_sha256"
            ],
            "index_execution_evaluation_sha256": request[
                "index_execution_evaluation_sha256"
            ],
            "independence_family": request["tool"][
                "independence_family"
            ],
            "observation_id": request["observation"][
                "observation_id"
            ],
            "operator_spec_sha256": request[
                "operator_spec_sha256"
            ],
            "plan_sha256": request["plan_sha256"],
            "pointer_id": request["pointer"]["pointer_id"],
            "pointer_kind": request["pointer"]["kind"],
            "pointer_sha256": request["pointer"]["sha256"],
            "protocol": FORENSIC_ASSERTION_EXECUTION_PROTOCOL,
            "readiness_registry_sha256": request[
                "readiness_registry_sha256"
            ],
            "receipt_id": request["observation"]["receipt_id"],
            "request_id": request["request_id"],
            "request_sha256": _sha256(request_payload),
            "run_id": request["run_id"],
            "runtime_image_digest": request["tool"][
                "runtime_image_digest"
            ],
            "schema_version": 1,
            "semantic_execution_contract_sha256": request[
                "semantic_execution_contract_sha256"
            ],
            "source_inventory_sha256": request["source"][
                "inventory_sha256"
            ],
            "source_manifest_sha256": request["source"][
                "manifest_sha256"
            ],
            "tool_id": request["tool"]["tool_id"],
            "tool_version_sha256": request["tool"][
                "tool_version_sha256"
            ],
            "transport": {
                "clean_workspace": True,
                "evidence_read_only": True,
                "exit_code": 0,
                "network_disabled": True,
                "orchestration_status": "completed",
                "timed_out": False,
            },
            "transport_execution_contract_sha256": request[
                "transport_contract"
            ]["transport_execution_contract_sha256"],
        }
        observation_path.write_bytes(_canonical(document))
        raw_root = self.work / "raw"
        raw_root.mkdir(parents=True, exist_ok=True)
        (raw_root / "stdout.log").write_bytes(b"")
        (raw_root / "stderr.log").write_bytes(b"")
        if self.owner.cherry_pick_request_ordinal == ordinal:
            assert self.owner.engine is not None
            state = self.owner.engine.store.load(
                self.owner.identity,
                recover=False,
            )
            attempt = next(
                reversed(
                    state.extra[
                        "forensic_assertion_preissues"
                    ].values()
                )
            )
            request_states = attempt["requests"]
            if len(request_states) > 1:
                root = self.owner.engine.store.challenge_paths(
                    self.owner.identity
                ).root
                first = root / request_states[0]["request"]["path"]
                second = root / request_states[1]["request"]["path"]
                second.chmod(0o600)
                second.write_bytes(first.read_bytes())
        if self.owner.mutate_source_ordinal == ordinal:
            assert self.owner.engine is not None
            source = (
                self.owner.engine.challenge_input(
                    self.owner.identity
                )
                / "traffic.pcapng"
            )
            source.write_bytes(source.read_bytes() + b":mutated")
        return SandboxResult(
            run_id=f"assertion-sandbox-{ordinal}",
            status="completed",
            exit_code=0,
            timed_out=False,
            duration_ms=4,
            stdout_summary="",
            stderr_summary="",
            stdout_bytes=0,
            stderr_bytes=0,
            stdout_path="/work/raw/stdout.log",
            stderr_path="/work/raw/stderr.log",
            stdout_stored_bytes=0,
            stderr_stored_bytes=0,
            stdout_limit_bytes=16 * 1024 * 1024,
            stderr_limit_bytes=16 * 1024 * 1024,
            stdout_truncated=False,
            stderr_truncated=False,
            stdout_truncation_known=True,
            stderr_truncation_known=True,
            stdout_capture_complete=True,
            stderr_capture_complete=True,
            orchestration_error=None,
        )

    def register_artifact(self, locator, *, maximum_bytes=1 << 34):
        path = self.work / locator
        payload = path.read_bytes()
        if len(payload) > maximum_bytes:
            raise ValueError("test capture exceeds bound")
        if (
            self.owner.mutate_durable_output_on_observation
            and "forensic-assertion-observations" in locator
        ):
            assert self.owner.engine is not None
            request_file = next(
                self.work.glob(
                    "runs/*/forensic-assertion/request.json"
                )
            )
            request = json.loads(request_file.read_bytes())
            root = self.owner.engine.store.challenge_paths(
                self.owner.identity
            ).root
            durable = root / request["artifact"]["path"]
            if durable.exists():
                durable.write_bytes(b"post-capture-cherry-pick")
        return ArtifactRef(
            locator=locator,
            sha256=_sha256(payload),
            size_bytes=len(payload),
            scope_fingerprint=self.scope_fingerprint,
        )

    def run_clean_proof(self, *args, **kwargs):
        raise AssertionError("assertion hotpath uses normal sandbox runs")

    def start_job(self, *args, **kwargs):
        raise AssertionError("not used")

    def job_status(self, *args, **kwargs):
        raise AssertionError("not used")

    def job_log(self, *args, **kwargs):
        raise AssertionError("not used")

    def cancel_job(self, *args, **kwargs):
        raise AssertionError("not used")


class ForensicAssertionHotPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.index_case = index_support.ForensicIndexHotPathTests(
            "test_explicit_seed_executes_and_authorizes_only_fact_progress"
        )
        self.index_case.setUp()
        self.engine, _holder = self.index_case._engine()
        self.identity = self.index_case.identity
        seed = self.index_case._bound_seed(self.engine)
        indexed = self.engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(seed.id,),
        )
        raw_index = next(
            experiment.result["forensic_index_execution"]
            for experiment in indexed.experiments
            if (
                type(experiment.result) is dict
                and "forensic_index_execution" in experiment.result
            )
        )
        index_execution = hotpath._typed_index_execution(raw_index)
        sources = hotpath._current_sources(self.engine, indexed)
        image_digest = self.engine.config.runtime.image_digest
        assert image_digest is not None
        readiness_payloads = {
            "alpha": b'{"ready":"alpha"}\n',
            "beta": b'{"ready":"beta"}\n',
        }
        readiness: list[ForensicToolReadiness] = []
        paths = self.engine.store.challenge_paths(self.identity)
        for name, family in (
            ("alpha", "family-alpha"),
            ("beta", "family-beta"),
        ):
            payload = readiness_payloads[name]
            readiness.append(
                ForensicToolReadiness(
                    tool_id=f"tool-{name}",
                    independence_family=family,
                    tool_version_sha256=_sha256(
                        f"tool:{name}:v1".encode()
                    ),
                    runtime_image_digest=image_digest,
                    supported_pointer_kinds=("file_range",),
                    command_template=(
                        f"/opt/ctf-tools/{name}",
                        "--request",
                        "{request_path}",
                        "--observation",
                        "{observation_path}",
                        "--artifact",
                        "{artifact_path}",
                    ),
                    readiness_generation=1,
                    readiness_artifact_id=f"READY-{name}",
                    readiness_artifact_sha256=_sha256(payload),
                    readiness_artifact_size_bytes=len(payload),
                )
            )
        self.readiness = tuple(readiness)
        registry_sha256 = forensic_tool_readiness_registry_sha256(
            self.readiness
        )
        source = next(
            item for item in sources if item.path == "traffic.pcapng"
        )
        pointer = ForensicFileRangePointer(
            pointer_id="PTR-traffic-header",
            source_path=source.path,
            source_sha256=source.sha256,
            offset_bytes=0,
            length_bytes=4,
        )
        assertion = ForensicAssertionNode(
            assertion_id="ASSERT-traffic-header",
            state=ForensicAssertionState.CONFIRMED,
            claim_kind="artifact_identity",
            claim_sha256=_sha256(b"traffic header is indexed"),
            depends_on=(),
            evidence_pointer_ids=(pointer.pointer_id,),
        )
        graph = build_forensic_assertion_graph_plan(
            index_execution=index_execution,
            expected_sources=sources,
            tools=tuple(
                item.tool_binding for item in self.readiness
            ),
            pointers=(pointer,),
            assertions=(assertion,),
        )
        self.operator_document = {
            "assertions": [assertion.to_dict()],
            "coverage_threshold_ppm": (
                FORENSIC_ASSERTION_MIN_COVERAGE_PPM
            ),
            "index_root": graph.inventory_root.to_dict(),
            "pointers": [pointer.to_dict()],
            "protocol": FORENSIC_ASSERTION_OPERATOR_SPEC_PROTOCOL,
            "readiness_registry_sha256": registry_sha256,
            "schema_version": 1,
            "source_catalog_sha256": graph.source_catalog_sha256,
            "tools": [item.to_dict() for item in self.readiness],
        }
        self.operator_payload = _canonical(self.operator_document)

        artifact_references: list[ArtifactReference] = []
        for item in self.readiness:
            payload = readiness_payloads[
                item.tool_id.removeprefix("tool-")
            ]
            relative = (
                "artifacts/forensic-readiness/"
                f"{item.readiness_artifact_id}.json"
            )
            destination = paths.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
            artifact_references.append(
                ArtifactReference(
                    id=item.readiness_artifact_id,
                    path=relative,
                    sha256=item.readiness_artifact_sha256,
                    size=item.readiness_artifact_size_bytes,
                    media_type="application/json",
                    extra={
                        "context_visibility": "engine_private",
                        "forensic_assertion_readiness": {
                            "configuration_epoch": (
                                indexed.configuration_epoch
                            ),
                            "confirmed": True,
                            "protocol": (
                                FORENSIC_ASSERTION_READINESS_PROTOCOL
                            ),
                            "readiness_registry_sha256": (
                                registry_sha256
                            ),
                            "schema_version": 1,
                            "tool": item.to_dict(),
                        },
                    },
                )
            )

        def append_readiness(state):
            state.artifacts.extend(copy.deepcopy(artifact_references))

        self.engine.store.update(
            self.identity,
            append_readiness,
            expected_revision=indexed.revision,
        )
        workspace = self.engine._workspace(
            self.engine.store.load(self.identity)
        )
        self.spec_locator = "forensic-assertion-spec.json"
        (workspace / self.spec_locator).write_bytes(
            self.operator_payload
        )
        self.coordinator = _AssertionCoordinator()
        self.coordinator.engine = self.engine
        self.coordinator.identity = self.identity
        self.engine._sandbox_factory = self.coordinator.factory

    def tearDown(self) -> None:
        self.index_case.tearDown()

    def _execute(self):
        return execute_forensic_assertion_hotpath(
            self.engine,
            self.identity,
            operator_spec_locator=self.spec_locator,
            timeout_seconds=120,
        )

    @staticmethod
    def _assertion_attempt(state):
        return next(
            reversed(
                state.extra["forensic_assertion_preissues"].values()
            )
        )

    def test_success_preissues_full_wave_and_authorizes_only_fact_progress(
        self,
    ) -> None:
        before = self.engine.store.load(self.identity)
        status = before.status
        candidate_count = len(before.candidates)
        submission_count = len(before.submissions)
        fact_count = len(before.facts)
        progress_count = len(before.progress_markers)
        state, evaluation = self._execute()
        self.assertTrue(evaluation.confirmed)
        self.assertEqual(len(evaluation.records), 2)
        self.assertEqual(state.status, status)
        self.assertEqual(len(state.candidates), candidate_count)
        self.assertEqual(len(state.submissions), submission_count)
        self.assertEqual(len(state.facts), fact_count + 1)
        self.assertEqual(
            len(state.progress_markers),
            progress_count + 1,
        )
        attempt = self._assertion_attempt(state)
        self.assertEqual(attempt["status"], "completed")
        self.assertEqual(
            attempt["terminal"]["reason_code"],
            "forensic_assertion_confirmed",
        )
        self.assertEqual(len(self.coordinator.pre_run_states), 2)
        first = self.coordinator.pre_run_states[0]
        self.assertTrue(first["all_request_files"])
        self.assertTrue(first["all_runs_preissued"])
        self.assertEqual(first["request_count"], 2)
        self.assertEqual(
            first["statuses"],
            ["running", "preissued"],
        )
        self.assertTrue(
            all(not policy.allow_targets for policy in self.coordinator.policies)
        )
        self.assertTrue(
            all(
                spec.network_target is None
                and spec.resource_request.network == 0
                and spec.summary_bytes == 0
                for spec in self.coordinator.command_specs
            )
        )
        encoded = json.dumps(state.to_dict(), sort_keys=True).encode()
        self.assertNotIn(b"forensic-observation:", encoded)

    def test_corrupt_observation_is_retained_but_rejected_without_fact(
        self,
    ) -> None:
        before = self.engine.store.load(self.identity)
        fact_count = len(before.facts)
        progress_count = len(before.progress_markers)
        self.coordinator.corrupt_observation_ordinal = 1
        state, evaluation = self._execute()
        self.assertFalse(evaluation.confirmed)
        self.assertIn(
            "artifact_capture_binding_mismatch",
            evaluation.reason_codes[0],
        )
        self.assertEqual(len(state.facts), fact_count)
        self.assertEqual(
            len(state.progress_markers),
            progress_count,
        )
        self.assertEqual(state.candidates, [])
        attempt = self._assertion_attempt(state)
        self.assertEqual(
            attempt["terminal"]["reason_code"],
            "forensic_assertion_rejected",
        )
        self.assertTrue(
            all(item["capture"] is not None for item in attempt["requests"])
        )
        assertion_runs = [
            run
            for run in state.runs
            if run.role == "forensic-assertion"
        ]
        self.assertEqual(assertion_runs, [])

    def test_source_toctou_terminalizes_without_authority(self) -> None:
        before = self.engine.store.load(self.identity)
        fact_count = len(before.facts)
        self.coordinator.mutate_source_ordinal = 1
        with self.assertRaises(ForensicAssertionHotPathError):
            self._execute()
        state = self.engine.store.load(self.identity, recover=False)
        attempt = self._assertion_attempt(state)
        self.assertEqual(attempt["status"], "interrupted")
        self.assertEqual(
            attempt["terminal"]["reason_code"],
            "forensic_assertion_execution_interrupted",
        )
        self.assertEqual(len(state.facts), fact_count)
        self.assertEqual(state.candidates, [])
        runs = [
            run
            for run in state.runs
            if run.extra.get("protocol")
            == FORENSIC_ASSERTION_HOTPATH_PROTOCOL
        ]
        self.assertEqual(len(runs), 2)
        self.assertTrue(
            all(run.status is RunStatus.INTERRUPTED for run in runs)
        )

    def test_preissued_request_cherry_pick_fails_before_second_tool(
        self,
    ) -> None:
        self.coordinator.cherry_pick_request_ordinal = 1
        with self.assertRaises(ForensicAssertionHotPathError):
            self._execute()
        state = self.engine.store.load(self.identity, recover=False)
        attempt = self._assertion_attempt(state)
        self.assertEqual(attempt["status"], "interrupted")
        self.assertEqual(self.coordinator.run_count, 1)
        self.assertEqual(state.candidates, [])
        invalidated = attempt["terminal"]["invalidated_artifact_ids"]
        self.assertEqual(len(invalidated), 1)
        self.assertFalse(
            any(
                artifact.id in invalidated
                for artifact in state.artifacts
            )
        )
        invalid_request = next(
            item["request"]["path"]
            for item in attempt["requests"]
            if item["request"]["request_id"] in invalidated
        )
        self.assertTrue(
            (
                self.engine.store.challenge_paths(self.identity).root
                / invalid_request
            ).is_file()
        )

    def test_post_capture_output_cherry_pick_fails_final_guard(
        self,
    ) -> None:
        self.coordinator.mutate_durable_output_on_observation = True
        with self.assertRaises(ForensicAssertionHotPathError):
            self._execute()
        state = self.engine.store.load(self.identity, recover=False)
        attempt = self._assertion_attempt(state)
        self.assertEqual(attempt["status"], "interrupted")
        self.assertEqual(state.candidates, [])
        self.assertFalse(
            any(
                type(experiment.result) is dict
                and "forensic_assertion_state" in experiment.result
                for experiment in state.experiments
            )
        )

    def test_keyboard_interrupt_terminalizes_all_preissued_runs(
        self,
    ) -> None:
        self.coordinator.interrupt_ordinal = 1
        with self.assertRaisesRegex(
            KeyboardInterrupt,
            "synthetic Forensic assertion interruption",
        ):
            self._execute()
        state = self.engine.store.load(self.identity, recover=False)
        attempt = self._assertion_attempt(state)
        self.assertEqual(attempt["status"], "interrupted")
        self.assertTrue(
            all(
                item["status"] == "interrupted"
                for item in attempt["requests"]
            )
        )
        runs = [
            run
            for run in state.runs
            if run.extra.get("protocol")
            == FORENSIC_ASSERTION_HOTPATH_PROTOCOL
        ]
        self.assertTrue(
            all(run.status is RunStatus.INTERRUPTED for run in runs)
        )

    def test_missing_confirmed_readiness_artifact_rejects_preflight(
        self,
    ) -> None:
        current = self.engine.store.load(self.identity)

        def strip_marker(state):
            artifact = next(
                item
                for item in state.artifacts
                if item.id == self.readiness[0].readiness_artifact_id
            )
            artifact.extra.clear()

        self.engine.store.update(
            self.identity,
            strip_marker,
            expected_revision=current.revision,
        )
        with self.assertRaises(ForensicAssertionHotPathError):
            self._execute()
        state = self.engine.store.load(self.identity)
        self.assertNotIn(
            "forensic_assertion_preissues",
            state.extra,
        )

    def test_invalid_timeout_does_not_open_an_attempt(self) -> None:
        with self.assertRaisesRegex(
            Exception,
            "timeout must be",
        ):
            execute_forensic_assertion_hotpath(
                self.engine,
                self.identity,
                operator_spec_locator=self.spec_locator,
                timeout_seconds=True,
            )
        state = self.engine.store.load(self.identity)
        self.assertNotIn(
            "forensic_assertion_preissues",
            state.extra,
        )


if __name__ == "__main__":
    unittest.main()
