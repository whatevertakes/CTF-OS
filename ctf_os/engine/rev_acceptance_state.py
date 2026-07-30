"""Exact durable graph for candidate-free Rev accepted-input evidence."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping

from ctf_os.engine.rev_acceptance import (
    REV_ACCEPTANCE_ATTEMPT_COUNT,
    REV_ACCEPTANCE_CONTROL_IDS,
    REV_ACCEPTANCE_POSITIVE_IDS,
    REV_ACCEPTANCE_PROTOCOL,
    RevAcceptanceOperatorSpec,
    canonical_json_bytes,
    validate_rev_acceptance_evaluation,
)
from ctf_os.models import (
    ChallengeState,
    ExperimentKind,
    ExperimentStatus,
    FactKind,
    Provenance,
    ReceiptOutcome,
    RunOrigin,
    RunStatus,
)


REV_ACCEPTANCE_ENGINE_COMMAND = "ctfos-engine:rev-accepted-input-v1"
REV_ACCEPTANCE_STATE_EXECUTOR = "rev_accepted_input_state_v1"
REV_ACCEPTANCE_STATE_RESULT_KEY = "rev_acceptance_evidence"
REV_ACCEPTANCE_STATE_SCHEMA_VERSION = 1

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BINDING_KEYS = frozenset(
    {
        "accepted_input_artifact",
        "authorities",
        "base_revision",
        "configuration_epoch",
        "evaluation",
        "evaluation_artifact_id",
        "evaluation_sha256",
        "experiment_id",
        "fact_id",
        "image_digest",
        "operator_spec",
        "operator_spec_artifact",
        "plan",
        "plan_sha256",
        "progress_id",
        "protocol",
        "records",
        "schema_version",
        "source",
    }
)
_ARTIFACT_BINDING_KEYS = frozenset(
    {"artifact_id", "path", "sha256", "size_bytes", "source_locator"}
)
_SOURCE_KEYS = frozenset(
    {
        "inventory_experiment_id",
        "inventory_receipt_id",
        "inventory_run_id",
        "inventory_stdout_artifact_id",
        "locator",
        "manifest_sha256",
        "sha256",
        "size_bytes",
    }
)
_PLAN_ITEM_KEYS = frozenset(
    {
        "input_sha256",
        "input_size_bytes",
        "mutation_id",
        "ordinal",
        "phase",
    }
)
_RECORD_KEYS = frozenset(
    {
        "observation",
        "request_path",
        "request_sha256",
        "request_size_bytes",
        "result_path",
        "result_sha256",
        "result_size_bytes",
        "validation_path",
        "validation_sha256",
        "validation_size_bytes",
    }
)
_OBSERVATION_KEYS = frozenset(
    {
        "capture_complete",
        "clean_workspace",
        "exit_code",
        "input_sha256",
        "input_size_bytes",
        "mutation_id",
        "network",
        "ordinal",
        "phase",
        "receipt_id",
        "run_id",
        "stderr_artifact_id",
        "stderr_sha256",
        "stderr_size_bytes",
        "stdout_artifact_id",
        "stdout_sha256",
        "stdout_size_bytes",
        "timed_out",
    }
)
_AUTHORITIES = {
    "automatic_submission_authorized": False,
    "candidate_authorized": False,
    "challenge_status_transition_authorized": False,
    "flag_proven": False,
}


def rev_acceptance_state_marker(value: object) -> bool:
    extra = getattr(value, "extra", None)
    result = getattr(value, "result", None)
    return (
        type(extra) is dict
        and (
            extra.get("engine_executor")
            == REV_ACCEPTANCE_STATE_EXECUTOR
            or "rev_acceptance_state" in extra
        )
    ) or (
        isinstance(result, Mapping)
        and REV_ACCEPTANCE_STATE_RESULT_KEY in result
    )


def _exact(
    value: object,
    keys: frozenset[str],
    label: str,
) -> Mapping[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise ValueError(f"{label} schema is not exact")
    return value


def _hash(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _integer(
    value: object,
    *,
    minimum: int = 0,
) -> bool:
    return type(value) is int and value >= minimum


def _artifact_binding(
    value: object,
    *,
    label: str,
) -> Mapping[str, object]:
    binding = _exact(value, _ARTIFACT_BINDING_KEYS, label)
    if (
        type(binding["artifact_id"]) is not str
        or not binding["artifact_id"]
        or type(binding["path"]) is not str
        or not binding["path"]
        or not _hash(binding["sha256"])
        or not _integer(binding["size_bytes"])
        or type(binding["source_locator"]) is not str
        or not binding["source_locator"]
    ):
        raise ValueError(f"{label} values are invalid")
    return binding


def _artifact_matches(
    artifact: object,
    binding: Mapping[str, object],
    *,
    source_run_id: str | None,
    expected_extra: Mapping[str, object],
) -> bool:
    return (
        artifact is not None
        and artifact.id == binding["artifact_id"]
        and artifact.path == binding["path"]
        and artifact.sha256 == binding["sha256"]
        and artifact.size == binding["size_bytes"]
        and artifact.source_run_id == source_run_id
        and artifact.extra == expected_extra
    )


def _expected_plan_shape(
    plan: list[Mapping[str, object]],
) -> bool:
    if len(plan) != REV_ACCEPTANCE_ATTEMPT_COUNT:
        return False
    mutation_ids = (*REV_ACCEPTANCE_POSITIVE_IDS, *REV_ACCEPTANCE_CONTROL_IDS)
    phases = ("positive", "positive", "positive", "control", "control", "control")
    if any(
        set(item) != _PLAN_ITEM_KEYS
        or item.get("ordinal") != index
        or item.get("phase") != phases[index - 1]
        or item.get("mutation_id") != mutation_ids[index - 1]
        or not _hash(item.get("input_sha256"))
        or not _integer(item.get("input_size_bytes"))
        for index, item in enumerate(plan, start=1)
    ):
        return False
    return (
        len({item["input_sha256"] for item in plan[:3]}) == 1
        and len({item["input_size_bytes"] for item in plan[:3]}) == 1
        and len({item["input_sha256"] for item in plan[3:]}) == 3
        and all(
            item["input_sha256"] != plan[0]["input_sha256"]
            for item in plan[3:]
        )
    )


def rev_acceptance_state_graph_errors(
    state: ChallengeState,
) -> list[str]:
    """Reconstruct every marker-scoped accepted-input evidence graph."""

    errors: list[str] = []
    experiments = {item.id: item for item in state.experiments}
    runs = {item.id: item for item in state.runs}
    receipts = {item.id: item for item in state.receipts}
    artifacts = {item.id: item for item in state.artifacts}
    facts = {item.id: item for item in state.facts}
    markers = {item.id: item for item in state.progress_markers}
    owned_runs: set[str] = set()
    owned_receipts: set[str] = set()
    owned_artifacts: set[str] = set()
    owned_facts: set[str] = set()
    owned_markers: set[str] = set()

    for experiment in state.experiments:
        if not rev_acceptance_state_marker(experiment):
            continue
        label = f"Rev accepted-input experiment {experiment.id}"
        try:
            result = _exact(
                experiment.result,
                frozenset({REV_ACCEPTANCE_STATE_RESULT_KEY}),
                "result",
            )
            binding = _exact(
                result[REV_ACCEPTANCE_STATE_RESULT_KEY],
                _BINDING_KEYS,
                "binding",
            )
            raw_evaluation = binding["evaluation"]
            evaluation = validate_rev_acceptance_evaluation(
                raw_evaluation
            )
            evaluation_sha256 = hashlib.sha256(
                canonical_json_bytes(evaluation)
            ).hexdigest()
            if (
                experiment.command != REV_ACCEPTANCE_ENGINE_COMMAND
                or experiment.kind is not ExperimentKind.PROBE
                or experiment.status
                is not (
                    ExperimentStatus.COMPLETED
                    if evaluation["passed"]
                    else ExperimentStatus.FAILED
                )
                or experiment.hypothesis_ids
                or experiment.proof_recipe is not None
                or experiment.extra
                != {
                    "engine_executor": REV_ACCEPTANCE_STATE_EXECUTOR,
                    "rev_acceptance_state": {
                        "evaluation_sha256": evaluation_sha256,
                        "protocol": REV_ACCEPTANCE_PROTOCOL,
                    },
                }
                or binding["protocol"] != REV_ACCEPTANCE_PROTOCOL
                or binding["schema_version"]
                != REV_ACCEPTANCE_STATE_SCHEMA_VERSION
                or binding["experiment_id"] != experiment.id
                or binding["authorities"] != _AUTHORITIES
                or not _integer(binding["configuration_epoch"])
                or binding["configuration_epoch"]
                > state.configuration_epoch
                or not _integer(binding["base_revision"])
                or binding["base_revision"] > state.revision
                or binding["image_digest"] != evaluation["image_digest"]
                or binding["evaluation_sha256"] != evaluation_sha256
            ):
                raise ValueError("experiment binding is inconsistent")

            spec = RevAcceptanceOperatorSpec.from_mapping(
                binding["operator_spec"]
            )
            spec_artifact_binding = _artifact_binding(
                binding["operator_spec_artifact"],
                label="operator spec artifact",
            )
            input_artifact_binding = _artifact_binding(
                binding["accepted_input_artifact"],
                label="accepted input artifact",
            )
            if (
                spec.evidence_sha256 != spec_artifact_binding["sha256"]
                or spec.accepted_input_locator
                != input_artifact_binding["source_locator"]
                or evaluation["operator_spec_sha256"]
                != spec.evidence_sha256
            ):
                raise ValueError("operator spec/input binding changed")
            spec_artifact = artifacts.get(
                spec_artifact_binding["artifact_id"]
            )
            input_artifact = artifacts.get(
                input_artifact_binding["artifact_id"]
            )
            if not _artifact_matches(
                spec_artifact,
                spec_artifact_binding,
                source_run_id=None,
                expected_extra={
                    "experiment_id": experiment.id,
                    "kind": "rev_acceptance_operator_spec",
                    "protocol": REV_ACCEPTANCE_PROTOCOL,
                    "rev_acceptance_state": True,
                    "source_locator": spec_artifact_binding[
                        "source_locator"
                    ],
                },
            ):
                raise ValueError("operator spec artifact is not exact")
            if not _artifact_matches(
                input_artifact,
                input_artifact_binding,
                source_run_id=None,
                expected_extra={
                    "experiment_id": experiment.id,
                    "kind": "rev_acceptance_input",
                    "protocol": REV_ACCEPTANCE_PROTOCOL,
                    "rev_acceptance_state": True,
                    "source_locator": spec.accepted_input_locator,
                },
            ):
                raise ValueError("accepted input artifact is not exact")

            raw_plan = binding["plan"]
            if (
                type(raw_plan) is not list
                or any(type(item) is not dict for item in raw_plan)
                or not _expected_plan_shape(raw_plan)
                or binding["plan_sha256"]
                != hashlib.sha256(
                    canonical_json_bytes(raw_plan)
                ).hexdigest()
                or evaluation["plan_sha256"] != binding["plan_sha256"]
                or raw_plan[0]["input_sha256"]
                != input_artifact_binding["sha256"]
                or raw_plan[0]["input_size_bytes"]
                != input_artifact_binding["size_bytes"]
            ):
                raise ValueError("attempt plan is inconsistent")

            source = _exact(binding["source"], _SOURCE_KEYS, "source")
            if (
                source["manifest_sha256"]
                != state.metadata.get("source_manifest_sha256")
                or source["locator"]
                != state.metadata.get("adapter_primary_source")
                or source["locator"] != spec.source_locator
                or evaluation["source_manifest_sha256"]
                != source["manifest_sha256"]
                or evaluation["source_sha256"] != source["sha256"]
                or evaluation["source_size_bytes"] != source["size_bytes"]
                or not _hash(source["sha256"])
                or not _integer(source["size_bytes"], minimum=1)
            ):
                raise ValueError("source binding is not current")
            inventory_experiment = experiments.get(
                source["inventory_experiment_id"]
            )
            inventory_run = runs.get(source["inventory_run_id"])
            inventory_receipt = receipts.get(
                source["inventory_receipt_id"]
            )
            inventory_stdout = artifacts.get(
                source["inventory_stdout_artifact_id"]
            )
            inventory_outcome = (
                inventory_experiment.result.get("partial_oracle")
                if inventory_experiment is not None
                and isinstance(inventory_experiment.result, Mapping)
                else None
            )
            inventory_semantic = (
                inventory_outcome.get("result")
                if isinstance(inventory_outcome, Mapping)
                else None
            )
            if (
                inventory_experiment is None
                or inventory_experiment.status
                is not ExperimentStatus.COMPLETED
                or inventory_run is None
                or inventory_run.status is not RunStatus.COMPLETED
                or inventory_run.origin
                not in {
                    RunOrigin.MANAGED_TOOL,
                    RunOrigin.OPERATOR_TOOL,
                }
                or inventory_receipt is None
                or inventory_receipt.outcome
                is not ReceiptOutcome.SUCCEEDED
                or inventory_receipt.run_id != inventory_run.id
                or inventory_receipt.experiment_id
                != inventory_experiment.id
                or inventory_receipt.stdout_artifact_id
                != source["inventory_stdout_artifact_id"]
                or inventory_stdout is None
                or inventory_stdout.source_run_id != inventory_run.id
                or not isinstance(inventory_semantic, Mapping)
                or inventory_semantic.get("verdict") != "CONFIRMED"
                or inventory_semantic.get("source_sha256")
                != source["sha256"]
                or inventory_semantic.get("source_size_bytes")
                != source["size_bytes"]
            ):
                raise ValueError("inventory evidence anchor is invalid")

            records = binding["records"]
            observations = evaluation["observations"]
            if (
                type(records) is not list
                or len(records) != REV_ACCEPTANCE_ATTEMPT_COUNT
                or len(observations) != REV_ACCEPTANCE_ATTEMPT_COUNT
            ):
                raise ValueError("execution record count is invalid")
            ordered_run_ids: list[str] = []
            ordered_receipt_ids: list[str] = []
            ordered_stream_artifact_ids: list[str] = []
            derived_reason_codes: list[str] = []
            observed_run_ids: set[str] = set()
            observed_receipt_ids: set[str] = set()
            observed_artifact_ids: set[str] = set()
            for index, (record_value, observation_value, plan_item) in enumerate(
                zip(records, observations, raw_plan, strict=True),
                start=1,
            ):
                record = _exact(
                    record_value,
                    _RECORD_KEYS,
                    f"record {index}",
                )
                observation = _exact(
                    record["observation"],
                    _OBSERVATION_KEYS,
                    f"observation {index}",
                )
                if observation != observation_value or any(
                    observation[field] != plan_item[field]
                    for field in (
                        "input_sha256",
                        "input_size_bytes",
                        "mutation_id",
                        "ordinal",
                        "phase",
                    )
                ):
                    raise ValueError(
                        f"observation {index} changed from its plan"
                    )
                expectation = (
                    spec.accepted
                    if index <= 3
                    else spec.controls[index - 4][1]
                )
                if (
                    observation["run_id"] in observed_run_ids
                    or observation["receipt_id"] in observed_receipt_ids
                    or observation["stdout_artifact_id"]
                    in observed_artifact_ids
                    or observation["stderr_artifact_id"]
                    in observed_artifact_ids
                    or observation["stdout_artifact_id"]
                    == observation["stderr_artifact_id"]
                ):
                    derived_reason_codes.append("identity_reused")
                observed_run_ids.add(observation["run_id"])
                observed_receipt_ids.add(observation["receipt_id"])
                observed_artifact_ids.update(
                    (
                        observation["stdout_artifact_id"],
                        observation["stderr_artifact_id"],
                    )
                )
                if (
                    observation["clean_workspace"] is not True
                    or observation["capture_complete"] is not True
                    or observation["timed_out"] is not False
                ):
                    derived_reason_codes.append(
                        f"attempt_{index}_transport_incomplete"
                    )
                if not expectation.matches(observation):
                    derived_reason_codes.append(
                        f"attempt_{index}_oracle_mismatch"
                    )
                for prefix in ("request", "result", "validation"):
                    if (
                        type(record[f"{prefix}_path"]) is not str
                        or not record[f"{prefix}_path"]
                        or not _hash(record[f"{prefix}_sha256"])
                        or not _integer(record[f"{prefix}_size_bytes"])
                    ):
                        raise ValueError(
                            f"record {index} {prefix} binding is invalid"
                        )
                run_id = observation["run_id"]
                receipt_id = observation["receipt_id"]
                stdout_id = observation["stdout_artifact_id"]
                stderr_id = observation["stderr_artifact_id"]
                run = runs.get(run_id)
                receipt = receipts.get(receipt_id)
                stdout = artifacts.get(stdout_id)
                stderr = artifacts.get(stderr_id)
                expected_run_extra = {
                    "experiment_id": experiment.id,
                    "request_sha256": record["request_sha256"],
                    "request_size_bytes": record["request_size_bytes"],
                    "result_sha256": record["result_sha256"],
                    "result_size_bytes": record["result_size_bytes"],
                    "rev_acceptance_state": {
                        "mutation_id": observation["mutation_id"],
                        "ordinal": index,
                        "protocol": REV_ACCEPTANCE_PROTOCOL,
                    },
                    "validation_sha256": record["validation_sha256"],
                    "validation_size_bytes": record[
                        "validation_size_bytes"
                    ],
                }
                if (
                    run is None
                    or run.status is not RunStatus.COMPLETED
                    or run.origin
                    not in {
                        RunOrigin.MANAGED_TOOL,
                        RunOrigin.OPERATOR_TOOL,
                    }
                    or run.role != "rev_acceptance_oracle"
                    or run.base_revision != binding["base_revision"]
                    or run.configuration_epoch
                    != binding["configuration_epoch"]
                    or run.request_path != record["request_path"]
                    or run.result_path != record["result_path"]
                    or run.validation_path != record["validation_path"]
                    or run.extra != expected_run_extra
                    or receipt is None
                    or receipt.outcome is not ReceiptOutcome.SUCCEEDED
                    or receipt.run_id != run.id
                    or receipt.experiment_id != experiment.id
                    or receipt.exit_code != observation["exit_code"]
                    or receipt.stdout_artifact_id != stdout_id
                    or receipt.stderr_artifact_id != stderr_id
                    or receipt.stdout_bytes
                    != observation["stdout_size_bytes"]
                    or receipt.stderr_bytes
                    != observation["stderr_size_bytes"]
                    or receipt.preview
                    != "Rev original-binary oracle attempt completed"
                    or receipt.extra
                    != {
                        "rev_acceptance_state": {
                            "mutation_id": observation["mutation_id"],
                            "ordinal": index,
                            "protocol": REV_ACCEPTANCE_PROTOCOL,
                        }
                    }
                ):
                    raise ValueError(
                        f"run/receipt {index} binding is inconsistent"
                    )
                stream_bindings = (
                    ("stdout", stdout, stdout_id),
                    ("stderr", stderr, stderr_id),
                )
                for stream_name, artifact, artifact_id in stream_bindings:
                    expected_extra = {
                        "experiment_id": experiment.id,
                        "kind": "rev_acceptance_stream",
                        "ordinal": index,
                        "protocol": REV_ACCEPTANCE_PROTOCOL,
                        "rev_acceptance_state": True,
                        "stream": stream_name,
                    }
                    if (
                        artifact is None
                        or artifact.source_run_id != run.id
                        or artifact.sha256
                        != observation[f"{stream_name}_sha256"]
                        or artifact.size
                        != observation[f"{stream_name}_size_bytes"]
                        or artifact.extra != expected_extra
                    ):
                        raise ValueError(
                            f"stream artifact {index}/{stream_name} "
                            "is inconsistent"
                        )
                    owned_artifacts.add(artifact_id)
                    ordered_stream_artifact_ids.append(artifact_id)
                owned_runs.add(run.id)
                owned_receipts.add(receipt.id)
                ordered_run_ids.append(run.id)
                ordered_receipt_ids.append(receipt.id)

            if evaluation["reason_codes"] != list(
                dict.fromkeys(derived_reason_codes)
            ):
                raise ValueError(
                    "evaluation reasons do not reconstruct from observations"
                )

            evaluation_artifact = artifacts.get(
                binding["evaluation_artifact_id"]
            )
            final_run_id = ordered_run_ids[-1]
            expected_evaluation_extra = {
                "evaluation_sha256": evaluation_sha256,
                "experiment_id": experiment.id,
                "kind": "rev_acceptance_evaluation",
                "protocol": REV_ACCEPTANCE_PROTOCOL,
                "rev_acceptance_state": True,
            }
            if (
                evaluation_artifact is None
                or evaluation_artifact.sha256 != evaluation_sha256
                or evaluation_artifact.size
                != len(canonical_json_bytes(evaluation))
                or evaluation_artifact.source_run_id != final_run_id
                or evaluation_artifact.extra
                != expected_evaluation_extra
            ):
                raise ValueError("evaluation artifact is not exact")
            owned_artifacts.update(
                {
                    spec_artifact.id,
                    input_artifact.id,
                    evaluation_artifact.id,
                }
            )
            expected_artifact_ids = [
                spec_artifact.id,
                input_artifact.id,
                *ordered_stream_artifact_ids,
                evaluation_artifact.id,
            ]
            if (
                experiment.artifact_ids != expected_artifact_ids
                or experiment.evidence_run_ids != ordered_run_ids
                or experiment.evidence_receipt_ids != ordered_receipt_ids
            ):
                raise ValueError(
                    "experiment evidence ordering is not exact"
                )

            fact_id = binding["fact_id"]
            progress_id = binding["progress_id"]
            if evaluation["passed"]:
                fact = facts.get(fact_id)
                marker = markers.get(progress_id)
                expected_marker = {
                    "evaluation_sha256": evaluation_sha256,
                    "protocol": REV_ACCEPTANCE_PROTOCOL,
                    "rev_acceptance_state": True,
                }
                if (
                    type(fact_id) is not str
                    or type(progress_id) is not str
                    or fact is None
                    or fact.provenance is not Provenance.EXECUTED
                    or fact.kind is not FactKind.OBSERVATION
                    or fact.statement
                    != (
                        "Original Rev binary accepted the exact input in "
                        "three clean runs and rejected three fixed mutations"
                    )
                    or fact.source_run_id != final_run_id
                    or fact.artifact_id != evaluation_artifact.id
                    or fact.locator != evaluation_artifact.path
                    or fact.extra != expected_marker
                    or marker is None
                    or marker.statement
                    != "Rev original-binary accepted-input oracle passed 3+3"
                    or marker.run_id != final_run_id
                    or marker.artifact_ids
                    != [evaluation_artifact.id, input_artifact.id]
                    or marker.extra != expected_marker
                    or experiment.evidence_fact_ids != [fact.id]
                ):
                    raise ValueError(
                        "passing fact/progress authority is inconsistent"
                    )
                owned_facts.add(fact.id)
                owned_markers.add(marker.id)
            elif (
                fact_id is not None
                or progress_id is not None
                or experiment.evidence_fact_ids
            ):
                raise ValueError(
                    "failed oracle retained Fact/Progress authority"
                )
        except (KeyError, TypeError, ValueError) as error:
            errors.append(f"{label} is invalid: {error}")

    for run in state.runs:
        if rev_acceptance_state_marker(run) and run.id not in owned_runs:
            errors.append(f"orphan Rev accepted-input run {run.id}")
    for receipt in state.receipts:
        if (
            rev_acceptance_state_marker(receipt)
            and receipt.id not in owned_receipts
        ):
            errors.append(
                f"orphan Rev accepted-input receipt {receipt.id}"
            )
    for artifact in state.artifacts:
        if (
            rev_acceptance_state_marker(artifact)
            and artifact.id not in owned_artifacts
        ):
            errors.append(
                f"orphan Rev accepted-input artifact {artifact.id}"
            )
    for fact in state.facts:
        if rev_acceptance_state_marker(fact) and fact.id not in owned_facts:
            errors.append(f"orphan Rev accepted-input fact {fact.id}")
    for marker in state.progress_markers:
        if (
            rev_acceptance_state_marker(marker)
            and marker.id not in owned_markers
        ):
            errors.append(
                f"orphan Rev accepted-input progress marker {marker.id}"
            )
    for candidate in state.candidates:
        if (
            rev_acceptance_state_marker(candidate)
            or any(run_id in owned_runs for run_id in candidate.proof_run_ids)
            or candidate.source_run_id in owned_runs
        ):
            errors.append(
                f"Rev accepted-input evidence promoted candidate {candidate.id}"
            )
    for submission in state.submissions:
        candidate = next(
            (
                item
                for item in state.candidates
                if item.id == submission.candidate_id
            ),
            None,
        )
        if candidate is not None and (
            candidate.source_run_id in owned_runs
            or any(run_id in owned_runs for run_id in candidate.proof_run_ids)
        ):
            errors.append(
                f"Rev accepted-input evidence promoted submission "
                f"{submission.id}"
            )
    return errors


def validate_rev_acceptance_state_graph(
    state: ChallengeState,
) -> None:
    errors = rev_acceptance_state_graph_errors(state)
    if errors:
        raise ValueError("; ".join(errors))


__all__ = [
    "REV_ACCEPTANCE_ENGINE_COMMAND",
    "REV_ACCEPTANCE_STATE_EXECUTOR",
    "REV_ACCEPTANCE_STATE_RESULT_KEY",
    "REV_ACCEPTANCE_STATE_SCHEMA_VERSION",
    "rev_acceptance_state_graph_errors",
    "rev_acceptance_state_marker",
    "validate_rev_acceptance_state_graph",
]
