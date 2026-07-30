from __future__ import annotations

import copy
import unittest

from ctf_os.engine.forensic_index import (
    ForensicIndexEvaluation,
    ForensicIndexVerdict,
)
from ctf_os.engine.forensic_index_execution import (
    ForensicIndexExecutionEnvelope,
    ForensicIndexExecutionEvaluation,
    ForensicIndexExecutionVerdict,
)
from ctf_os.models import (
    ChallengeState,
    ExperimentStatus,
    ModelValidationError,
    validate_forensic_index_execution_state_graph,
)
from tests import test_forensic_hotpath as hotpath_support


def _execution_experiment(state: ChallengeState):
    return next(
        experiment
        for experiment in state.experiments
        if (
            type(experiment.result) is dict
            and "forensic_index_execution" in experiment.result
        )
    )


def _graph_records(state: ChallengeState):
    experiment = _execution_experiment(state)
    run = next(
        item
        for item in state.runs
        if item.id == experiment.result["run_id"]
    )
    receipt = next(
        item
        for item in state.receipts
        if item.id == experiment.result["receipt_id"]
    )
    evaluation_artifact = next(
        item
        for item in state.artifacts
        if item.id
        == experiment.result["forensic_index_evaluation_artifact_id"]
    )
    stdout = next(
        item
        for item in state.artifacts
        if item.id == receipt.stdout_artifact_id
    )
    stderr = next(
        item
        for item in state.artifacts
        if item.id == receipt.stderr_artifact_id
    )
    return (
        experiment,
        run,
        receipt,
        evaluation_artifact,
        stdout,
        stderr,
    )


def _execution_payloads(state: ChallengeState) -> tuple[dict, ...]:
    experiment, run, receipt, *_ = _graph_records(state)
    return (
        experiment.result["forensic_index_execution"],
        run.extra["forensic_index_execution"],
        receipt.extra["forensic_index_execution"],
    )


def _set_payload_path(
    state: ChallengeState,
    path: tuple[str, ...],
    value: object,
) -> None:
    for payload in _execution_payloads(state):
        target = payload
        for component in path[:-1]:
            target = target[component]
        target[path[-1]] = value


def _semantic_rejected_state(
    confirmed: ChallengeState,
) -> ChallengeState:
    state = copy.deepcopy(confirmed)
    experiment, run, receipt, evaluation_artifact, *_ = (
        _graph_records(state)
    )
    raw = experiment.result["forensic_index_execution"]["envelope"]
    envelope = ForensicIndexExecutionEnvelope(
        category=raw["category"],
        contest_id=raw["contest_id"],
        challenge_id=raw["challenge_id"],
        configuration_epoch=raw["configuration_epoch"],
        experiment_id=raw["experiment_id"],
        run_id=raw["run"]["id"],
        run_origin=raw["run"]["origin"],
        request_path=raw["request"]["path"],
        request_sha256=raw["request"]["sha256"],
        request_size_bytes=raw["request"]["size_bytes"],
        result_path=raw["run"]["result_path"],
        validation_path=raw["run"]["validation_path"],
        receipt_id=raw["receipt"]["id"],
        image_name=raw["image"]["name"],
        image_digest=raw["image"]["digest"],
        source_manifest_sha256=raw["source"]["manifest_sha256"],
        source_inventory_sha256=raw["source"]["inventory_sha256"],
        source_file_count=raw["source"]["file_count"],
        source_total_bytes=raw["source"]["total_bytes"],
        prefix_coverage_ppm=raw["prefix_coverage_ppm"],
        stdout_artifact_id=raw["stdout_artifact"]["id"],
        stdout_artifact_path=raw["stdout_artifact"]["path"],
        stdout_artifact_sha256=raw["stdout_artifact"]["sha256"],
        stdout_artifact_size_bytes=raw["stdout_artifact"][
            "size_bytes"
        ],
    )
    semantic = ForensicIndexEvaluation(
        verdict=ForensicIndexVerdict.REJECTED,
        reason_code="index_hash_mismatch",
        source_inventory_sha256=envelope.source_inventory_sha256,
        tree_sha256=None,
        index_sha256=None,
        indexed_files=0,
        indexed_bytes=0,
        pointer_coverage_ppm=0,
        modality_counts=(),
    )
    evaluation = ForensicIndexExecutionEvaluation(
        verdict=ForensicIndexExecutionVerdict.REJECTED,
        reason_code="semantic_index_hash_mismatch",
        envelope=envelope,
        semantic_evaluation=semantic,
    )
    payload = evaluation.to_dict()
    experiment.result["forensic_index_execution"] = copy.deepcopy(
        payload
    )
    run.extra["forensic_index_execution"] = copy.deepcopy(payload)
    receipt.extra["forensic_index_execution"] = copy.deepcopy(payload)
    experiment.status = ExperimentStatus.FAILED
    experiment.evaluation_reason = (
        "forensic_index:REJECTED:semantic_index_hash_mismatch"
    )
    experiment.evidence_fact_ids = []
    state.facts = [
        fact
        for fact in state.facts
        if "forensic_evidence_index" not in fact.extra
    ]
    state.progress_markers = [
        marker
        for marker in state.progress_markers
        if "forensic_evidence_index" not in marker.extra
    ]
    evaluation_artifact.sha256 = evaluation.sha256
    evaluation_artifact.size = len(evaluation.canonical_bytes)
    evaluation_artifact.extra["evaluation_sha256"] = evaluation.sha256
    return state


class ForensicIndexStateGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        confirmed_case = hotpath_support.ForensicIndexHotPathTests(
            "test_explicit_seed_executes_and_authorizes_only_fact_progress"
        )
        confirmed_case.setUp()
        try:
            engine, _holder = confirmed_case._engine()
            seed = confirmed_case._bound_seed(engine)
            cls.confirmed = copy.deepcopy(
                engine.execute_registered_experiments(
                    confirmed_case.identity,
                    experiment_ids=(seed.id,),
                )
            )
        finally:
            confirmed_case.tearDown()

        rejected_case = hotpath_support.ForensicIndexHotPathTests(
            "test_source_mutation_during_transport_fails_closed"
        )
        rejected_case.setUp()
        try:
            source = (
                rejected_case.root
                / "incoming"
                / rejected_case.identity.contest_id
                / rejected_case.identity.category
                / rejected_case.identity.challenge_id
                / "traffic.pcapng"
            )
            engine, _holder = rejected_case._engine(
                mutate_source=lambda: source.write_bytes(b"mutated")
            )
            seed = rejected_case._bound_seed(engine)
            cls.rejected = copy.deepcopy(
                engine.execute_registered_experiments(
                    rejected_case.identity,
                    experiment_ids=(seed.id,),
                )
            )
        finally:
            rejected_case.tearDown()
        cls.semantic_rejected = _semantic_rejected_state(cls.confirmed)

    def _assert_invalid(
        self,
        state: ChallengeState,
        pattern: str = "Forensic",
    ) -> None:
        with self.assertRaisesRegex(ModelValidationError, pattern):
            validate_forensic_index_execution_state_graph(state)

    def test_confirmed_and_rejected_graphs_validate(self) -> None:
        for label, state in (
            ("confirmed", self.confirmed),
            ("early rejected", self.rejected),
            ("semantic rejected", self.semantic_rejected),
        ):
            with self.subTest(label=label):
                validate_forensic_index_execution_state_graph(state)
                state.validate()

    def test_orphan_evaluation_fact_progress_run_and_receipt_rejected(
        self,
    ) -> None:
        mutations = {}

        def orphan_artifact(state):
            _experiment, _run, _receipt, artifact, *_ = (
                _graph_records(state)
            )
            orphan = copy.deepcopy(artifact)
            orphan.id = "A-forensic-orphan-evaluation"
            orphan.path = (
                "artifacts/snapshots/"
                "A-forensic-orphan-evaluation.json"
            )
            state.artifacts.append(orphan)

        mutations["evaluation artifact"] = orphan_artifact

        def orphan_fact(state):
            orphan = copy.deepcopy(state.facts[-1])
            orphan.id = "F-forensic-orphan"
            orphan.extra["forensic_evidence_index"][
                "evaluation_sha256"
            ] = "0" * 64
            state.facts.append(orphan)

        mutations["fact"] = orphan_fact

        def orphan_progress(state):
            orphan = copy.deepcopy(state.progress_markers[-1])
            orphan.id = "P-forensic-orphan"
            orphan.extra["forensic_evidence_index"][
                "evaluation_sha256"
            ] = "0" * 64
            state.progress_markers.append(orphan)

        mutations["progress"] = orphan_progress

        def orphan_run(state):
            _experiment, run, *_ = _graph_records(state)
            orphan = copy.deepcopy(run)
            orphan.id = "RUN-forensic-orphan"
            state.runs.append(orphan)

        mutations["run"] = orphan_run

        def orphan_receipt(state):
            _experiment, _run, receipt, *_ = _graph_records(state)
            orphan = copy.deepcopy(receipt)
            orphan.id = "RCPT-forensic-orphan"
            state.receipts.append(orphan)

        mutations["receipt"] = orphan_receipt

        for label, mutate in mutations.items():
            with self.subTest(node=label):
                state = copy.deepcopy(self.confirmed)
                mutate(state)
                self._assert_invalid(state, "orphan|lacks exact")

    def test_payload_authority_hash_and_copy_forgery_rejected(self) -> None:
        mutations = {
            "authority": lambda state: (
                _execution_experiment(state)
                .result["forensic_index_execution"]["authorities"]
                .__setitem__("candidate_authorized", True)
            ),
            "inner hash": lambda state: (
                _execution_experiment(state)
                .result["forensic_index_execution"]
                .__setitem__("envelope_sha256", "0" * 64)
            ),
            "run copy": lambda state: (
                _graph_records(state)[1]
                .extra["forensic_index_execution"]
                .__setitem__("reason_code", "forged")
            ),
            "receipt copy": lambda state: (
                _graph_records(state)[2]
                .extra["forensic_index_execution"]
                .__setitem__("reason_code", "forged")
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(forgery=label):
                state = copy.deepcopy(self.confirmed)
                mutate(state)
                self._assert_invalid(state)

    def test_evaluation_artifact_binding_is_exact(self) -> None:
        def wrong_sha(state):
            _graph_records(state)[3].sha256 = "0" * 64

        def wrong_size(state):
            _graph_records(state)[3].size += 1

        def wrong_experiment(state):
            _graph_records(state)[3].extra[
                "experiment_id"
            ] = "E-forged"

        def extra_authority(state):
            _graph_records(state)[3].extra[
                "candidate_authorized"
            ] = True

        for label, mutate in (
            ("sha", wrong_sha),
            ("size", wrong_size),
            ("experiment", wrong_experiment),
            ("unknown authority", extra_authority),
        ):
            with self.subTest(binding=label):
                state = copy.deepcopy(self.confirmed)
                mutate(state)
                self._assert_invalid(state, "artifact binding")

    def test_run_receipt_stdout_source_config_and_image_rebinding_rejected(
        self,
    ) -> None:
        def wrong_run(state):
            _execution_experiment(state).result["run_id"] = "RUN-forged"

        def wrong_receipt(state):
            _execution_experiment(state).result[
                "receipt_id"
            ] = "RCPT-forged"

        def wrong_stdout(state):
            _graph_records(state)[2].stdout_artifact_id = "A-forged"

        def wrong_source(state):
            state.metadata["source_manifest_sha256"] = "0" * 64

        def wrong_config(state):
            _graph_records(state)[1].configuration_epoch += 1

        def wrong_image(state):
            payload = _execution_experiment(state).result[
                "forensic_index_execution"
            ]
            payload["envelope"]["image"]["digest"] = (
                "sha256:" + ("0" * 64)
            )

        for label, mutate in (
            ("run", wrong_run),
            ("receipt", wrong_receipt),
            ("stdout", wrong_stdout),
            ("source", wrong_source),
            ("configuration", wrong_config),
            ("image", wrong_image),
        ):
            with self.subTest(binding=label):
                state = copy.deepcopy(self.confirmed)
                mutate(state)
                self._assert_invalid(state)

    def test_confirmed_and_rejected_status_authority_mismatch_rejected(
        self,
    ) -> None:
        state = copy.deepcopy(self.confirmed)
        _execution_experiment(state).status = ExperimentStatus.FAILED
        self._assert_invalid(state, "status")

        state = copy.deepcopy(self.confirmed)
        state.facts.clear()
        self._assert_invalid(state, "lacks exact")

        state = copy.deepcopy(self.confirmed)
        state.progress_markers.clear()
        self._assert_invalid(state, "lacks exact")

        state = copy.deepcopy(self.rejected)
        _execution_experiment(state).status = ExperimentStatus.COMPLETED
        self._assert_invalid(state, "status")

        state = copy.deepcopy(self.rejected)
        forged = copy.deepcopy(self.confirmed.facts[-1])
        forged.id = "F-rejected-forged-authority"
        state.facts.append(forged)
        self._assert_invalid(state, "orphan")

    def test_graph_ids_must_be_globally_distinct(self) -> None:
        state = copy.deepcopy(self.confirmed)
        state.progress_markers[-1].id = state.facts[-1].id
        self._assert_invalid(state, "duplicated globally")

    def test_confirmed_bool_integer_aliases_fail_closed(self) -> None:
        aliases = {
            "root schema": (
                ("schema_version",),
                True,
            ),
            "semantic schema": (
                ("semantic_evaluation", "schema_version"),
                True,
            ),
            "envelope schema": (
                ("envelope", "schema_version"),
                True,
            ),
            "authority": (
                ("authorities", "candidate_authorized"),
                0,
            ),
            "semantic claim": (
                (
                    "semantic_evaluation",
                    "claims",
                    "candidate_ready",
                ),
                0,
            ),
            "transport boolean": (
                ("envelope", "transport", "capture_complete"),
                1,
            ),
            "receipt exit": (
                ("envelope", "receipt", "exit_code"),
                False,
            ),
        }
        for label, (path, value) in aliases.items():
            with self.subTest(alias=label):
                state = copy.deepcopy(self.confirmed)
                _set_payload_path(state, path, value)
                self._assert_invalid(state)

    def test_rejected_and_seed_bool_integer_aliases_fail_closed(
        self,
    ) -> None:
        state = copy.deepcopy(self.rejected)
        _set_payload_path(state, ("schema_version",), True)
        self._assert_invalid(state)

        state = copy.deepcopy(self.rejected)
        _execution_experiment(state).result["exit_code"] = False
        self._assert_invalid(state)

        state = copy.deepcopy(self.rejected)
        experiment, run, *_ = _graph_records(state)
        experiment.extra["adapter_seed_contract_version"] = True
        run.extra["adapter_seed_contract_version"] = True
        self._assert_invalid(state, "seed/source")

        state = copy.deepcopy(self.rejected)
        experiment, run, *_ = _graph_records(state)
        experiment.extra["source_binding"]["schema_version"] = True
        run.extra["source_binding"]["schema_version"] = True
        state.metadata["adapter_seed_source_binding"][
            "schema_version"
        ] = True
        self._assert_invalid(state, "seed/source")

        state = copy.deepcopy(self.rejected)
        state.configuration_epoch = False
        _graph_records(state)[1].configuration_epoch = False
        self._assert_invalid(state, "source/configuration")

    def test_public_validator_rejects_non_state(self) -> None:
        with self.assertRaisesRegex(
            ModelValidationError,
            "requires ChallengeState",
        ):
            validate_forensic_index_execution_state_graph({})


if __name__ == "__main__":
    unittest.main()
