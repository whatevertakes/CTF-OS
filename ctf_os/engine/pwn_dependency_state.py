"""Exact, raw-free Pwn D->V->(L|N/A)->P->E dependency state.

This module does not create another Pwn oracle.  It closes the evidence
topology after the existing deterministic oracles have already completed:

``D``
    One immutable trigger artifact and its originating hypothesis/run.
``V``
    The exact six-replay confirmed crash result.
``L``
    One exact three-replay ``PwnLeakResult(PROVEN)`` for the same runtime
    snapshot, when present.
``N/A``
    A dependency-scoped, retrospective engine judgement.  It exists only
    after both the exact instruction-pointer primitive and exact exploit
    effect have been observed for the same immutable target.  It never uses
    PIE/non-PIE metadata or ``pwn_leak_requirement_v1`` as authority.
``P``
    The exact three-replay instruction-pointer-control result.
``E``
    The exact six-replay exploit-effect result.

The N/A node is intentionally represented with two topologies.  The gate
topology is ``D -> V -> N/A -> P -> E``.  The evidence topology records
``P -> N/A`` and ``E -> N/A`` because the N/A certificate is retrospective;
it is not allowed to pretend that it chronologically authorized P or E.

Every selected experiment, run, receipt, artifact, hypothesis, Fact, and
progress marker is committed by exact canonical-record hash.  The projection
contains only identifiers, hashes, sizes, state revisions, and safe paths.
It contains no payload, target output, register dump, map contents, flag
candidate, proof claim, or submission authority.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from ctf_os.contracts.pwn_leak_requirement_v1 import (
    PWN_LEAK_REQUIREMENT_V1_CONTRACT_FINGERPRINT,
    PWN_LEAK_REQUIREMENT_V1_CONTRACT_ID,
)
from ctf_os.engine.pwn_exploit_effect import (
    PwnExploitEffectReplayCommitment,
    PwnExploitEffectResult,
    PwnExploitEffectStatus,
    pwn_exploit_effect_child_experiment_id,
)
from ctf_os.engine.pwn_exploit_effect_state import (
    PWN_EXPLOIT_EFFECT_STATE_EXECUTOR,
    PWN_EXPLOIT_EFFECT_STATE_PROTOCOL,
    validate_pwn_exploit_effect_state_graph,
)
from ctf_os.engine.pwn_ip_control import (
    PWN_IP_CONTROL_REPLAY_COUNT,
    PwnIpControlResult,
    PwnIpControlStatus,
)
from ctf_os.engine.pwn_leak import (
    PWN_LEAK_REPLAY_COUNT,
    PwnLeakReplayCommitment,
    PwnLeakResult,
    PwnLeakStatus,
)
from ctf_os.models import (
    ArtifactReference,
    ChallengeState,
    ExecutionReceipt,
    Experiment,
    ExperimentStatus,
    Fact,
    Hypothesis,
    ProgressMarker,
    RunReference,
    RunStatus,
)
from ctf_os.sandbox.files import SafeFileError, read_bounded_regular
from ctf_os.stages.ingest import inventory_challenge


PWN_DEPENDENCY_STATE_PROTOCOL = "ctfos.pwn.dependency_state.v1"
PWN_DEPENDENCY_STATE_SCHEMA_VERSION = 1
PWN_DEPENDENCY_STATE_JOURNAL_KEY = "pwn_dependency_graphs"
PWN_DEPENDENCY_CONTEXT_PROTOCOL = "ctfos.pwn.dependency_context.v1"
PWN_DEPENDENCY_STATE_MAX_BYTES = 2 * 1024 * 1024
PWN_DEPENDENCY_STATE_MAX_OBJECTS = 512
PWN_DEPENDENCY_STATE_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:@-]{0,2047}$")
_TERMINAL_RUN_STATUSES = frozenset(
    {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.TIMED_OUT}
)
_AUTHORITIES = {
    "automatic_submission_authorized": False,
    "candidate_authorized": False,
    "challenge_proof_satisfied": False,
    "challenge_status_transition_authorized": False,
    "flag_proven": False,
    "model_self_report_accepted": False,
    "proof_authorized": False,
    "submission_authorized": False,
    "dependency_chain_proven": True,
}
_DEPENDENCY_CLAIMS_FALSE = {
    "global_leak_not_applicable_proven": False,
    "global_runtime_address_resolution_not_applicable_proven": False,
    "leak_proven": False,
    "leak_required_proven": False,
    "primitive_proven": True,
    "proof_satisfied": False,
    "stage_advance_authorized": False,
}


class PwnDependencyStateError(ValueError):
    """Stable fail-closed error for an invalid dependency graph."""


@dataclass(frozen=True, slots=True)
class _ResolvedChain:
    discovery: Experiment
    snapshot: Experiment
    leak: Experiment | None
    primitive: Experiment
    effect: Experiment
    primitive_result: PwnIpControlResult
    effect_result: PwnExploitEffectResult
    effect_binding: dict[str, object]
    leak_result: PwnLeakResult | None


def _canonical_bytes(
    value: object,
    *,
    maximum_bytes: int = PWN_DEPENDENCY_STATE_MAX_BYTES,
) -> bytes:
    try:
        payload = (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise PwnDependencyStateError(
            "dependency_graph_not_canonical_json"
        ) from error
    if len(payload) > maximum_bytes:
        raise PwnDependencyStateError("dependency_graph_too_large")
    return payload


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _exact_dict(
    value: object,
    keys: Iterable[str],
    code: str,
) -> dict[str, object]:
    expected = frozenset(keys)
    if type(value) is not dict or set(value) != expected:
        raise PwnDependencyStateError(code)
    return value


def _require_sha256(value: object, code: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise PwnDependencyStateError(code)
    return value


def _experiment_record(value: Experiment) -> dict[str, object]:
    return value.to_dict(v2=True)


def _run_record(value: RunReference) -> dict[str, object]:
    return value.to_dict(v2=True)


def _receipt_record(value: ExecutionReceipt) -> dict[str, object]:
    return value.to_dict()


def _artifact_record(value: ArtifactReference) -> dict[str, object]:
    return value.to_dict()


def _hypothesis_record(value: Hypothesis) -> dict[str, object]:
    return value.to_dict(v2=True)


def _fact_record(
    value: Fact,
    *,
    challenge_id: str,
) -> dict[str, object]:
    return value.to_dict(
        default_challenge_id=challenge_id,
        v2=True,
    )


def _progress_record(value: ProgressMarker) -> dict[str, object]:
    return value.to_dict()


def _lookup_unique(
    values: Iterable[object],
    identifier: str,
    code: str,
) -> object:
    selected = [
        value for value in values if getattr(value, "id", None) == identifier
    ]
    if len(selected) != 1:
        raise PwnDependencyStateError(code)
    return selected[0]


def _safe_result_envelope(
    experiment: Experiment,
    key: str,
    code: str,
) -> dict[str, object]:
    if (
        type(experiment.result) is not dict
        or set(experiment.result) != {key}
        or type(experiment.result[key]) is not dict
    ):
        raise PwnDependencyStateError(code)
    return experiment.result[key]


def _effect_from_state(
    state: ChallengeState,
    effect_experiment_id: str,
) -> tuple[
    Experiment,
    PwnExploitEffectResult,
    dict[str, object],
]:
    effect = _lookup_unique(
        state.experiments,
        effect_experiment_id,
        "effect_experiment_missing_or_duplicated",
    )
    assert isinstance(effect, Experiment)
    marker = _exact_dict(
        effect.extra.get("pwn_exploit_effect_state"),
        {"binding", "binding_sha256", "marker", "protocol"},
        "effect_state_marker_invalid",
    )
    if (
        effect.extra.get("engine_executor")
        != PWN_EXPLOIT_EFFECT_STATE_EXECUTOR
        or effect.status is not ExperimentStatus.COMPLETED
        or marker["protocol"] != PWN_EXPLOIT_EFFECT_STATE_PROTOCOL
        or type(marker["binding"]) is not dict
        or marker["binding_sha256"] != _sha256(marker["binding"])
    ):
        raise PwnDependencyStateError("effect_state_not_exact_final")
    binding = marker["binding"]
    assert isinstance(binding, dict)
    chronology = binding.get("chronology")
    experiment_binding = binding.get("experiment")
    if (
        type(chronology) is not dict
        or chronology.get("phase") != "final"
        or chronology.get("terminal") is not True
        or type(experiment_binding) is not dict
        or experiment_binding.get("id") != effect.id
    ):
        raise PwnDependencyStateError("effect_state_not_terminal")
    raw_result = binding.get("result")
    try:
        if type(raw_result) is not dict:
            raise ValueError("effect result is not an object")
        result_binding = raw_result["binding"]
        if type(result_binding) is not dict:
            raise ValueError("effect result binding is not an object")
        independently_reconstructed = PwnExploitEffectResult(
            status=PwnExploitEffectStatus(raw_result["status"]),
            reason_code=raw_result["reason_code"],
            plan_recipe_sha256=result_binding[
                "plan_recipe_sha256"
            ],
            trusted_expectation_sha256=result_binding[
                "trusted_expectation_sha256"
            ],
            parent_ip_control_evidence_sha256=result_binding[
                "parent_ip_control_evidence_sha256"
            ],
            source_manifest_sha256=result_binding[
                "source_manifest_sha256"
            ],
            source_sha256=result_binding["source_sha256"],
            source_size_bytes=result_binding["source_size_bytes"],
            exploit_payload_sha256=result_binding[
                "exploit_payload_sha256"
            ],
            exploit_payload_size_bytes=result_binding[
                "exploit_payload_size_bytes"
            ],
            controlled_offset=result_binding["controlled_offset"],
            replays=tuple(
                PwnExploitEffectReplayCommitment.from_dict(item)
                for item in raw_result["replays"]
            ),
        )
        result = PwnExploitEffectResult.from_dict(
            raw_result,
            expected_result=independently_reconstructed,
        )
    except (TypeError, ValueError) as error:
        raise PwnDependencyStateError(
            "effect_result_invalid"
        ) from error
    if (
        result.status is not PwnExploitEffectStatus.PROVEN
        or not result.exploit_effect_proven
    ):
        raise PwnDependencyStateError("effect_not_proven")
    parent_id = experiment_binding.get("parent_experiment_id")
    if (
        type(parent_id) is not str
        or effect.id
        != pwn_exploit_effect_child_experiment_id(parent_id)
    ):
        raise PwnDependencyStateError(
            "effect_production_identity_invalid"
        )
    return effect, result, binding


def _primitive_from_state(
    state: ChallengeState,
    effect_binding: Mapping[str, object],
) -> tuple[Experiment, PwnIpControlResult]:
    experiment_binding = effect_binding.get("experiment")
    if type(experiment_binding) is not dict:
        raise PwnDependencyStateError("effect_parent_binding_invalid")
    parent_id = experiment_binding.get("parent_experiment_id")
    if type(parent_id) is not str:
        raise PwnDependencyStateError("effect_parent_binding_invalid")
    primitive = _lookup_unique(
        state.experiments,
        parent_id,
        "primitive_experiment_missing_or_duplicated",
    )
    assert isinstance(primitive, Experiment)
    envelope = _safe_result_envelope(
        primitive,
        "pwn_ip_control_evidence",
        "primitive_result_envelope_invalid",
    )
    try:
        result = PwnIpControlResult.from_dict(envelope.get("result"))
    except (TypeError, ValueError) as error:
        raise PwnDependencyStateError(
            "primitive_result_invalid"
        ) from error
    result_artifact_id = envelope.get("result_artifact_id")
    result_artifact = (
        _lookup_unique(
            state.artifacts,
            result_artifact_id,
            "primitive_result_artifact_missing_or_duplicated",
        )
        if type(result_artifact_id) is str
        else None
    )
    if (
        primitive.extra.get("engine_executor") != "pwn_ip_control_v1"
        or primitive.status is not ExperimentStatus.COMPLETED
        or result.status is not PwnIpControlStatus.PROVEN
        or not result.instruction_pointer_control_proven
        or envelope.get("result_sha256") != result.evidence_sha256
        or envelope.get("plan_recipe_sha256")
        != result.plan_recipe_sha256
        or envelope.get("run_ids") != primitive.evidence_run_ids
        or envelope.get("receipt_ids")
        != primitive.evidence_receipt_ids
        or len(primitive.evidence_run_ids) != PWN_IP_CONTROL_REPLAY_COUNT
        or len(primitive.evidence_receipt_ids)
        != PWN_IP_CONTROL_REPLAY_COUNT
        or not isinstance(result_artifact, ArtifactReference)
        or result_artifact.sha256 != result.evidence_sha256
        or result_artifact.id not in primitive.artifact_ids
    ):
        raise PwnDependencyStateError("primitive_state_not_exact_proven")
    return primitive, result


def _snapshot_and_discovery(
    state: ChallengeState,
    primitive: Experiment,
) -> tuple[Experiment, Experiment]:
    snapshot_id = primitive.extra.get("baseline_experiment_id")
    if type(snapshot_id) is not str:
        raise PwnDependencyStateError("snapshot_dependency_missing")
    snapshot = _lookup_unique(
        state.experiments,
        snapshot_id,
        "snapshot_experiment_missing_or_duplicated",
    )
    assert isinstance(snapshot, Experiment)
    snapshot_envelope = _safe_result_envelope(
        snapshot,
        "pwn_runtime_snapshot_evidence",
        "snapshot_result_envelope_invalid",
    )
    snapshot_evaluation = snapshot_envelope.get("evaluation")
    discovery_id = snapshot.extra.get("parent_experiment_id")
    if (
        snapshot.extra.get("engine_executor")
        != "pwn_runtime_snapshot_v1"
        or snapshot.status is not ExperimentStatus.COMPLETED
        or type(snapshot_evaluation) is not dict
        or snapshot_evaluation.get("status") != "CAPTURED"
        or snapshot_envelope.get("evaluation_sha256")
        != _sha256(snapshot_evaluation)
        or type(discovery_id) is not str
    ):
        raise PwnDependencyStateError("snapshot_state_not_exact_captured")
    discovery = _lookup_unique(
        state.experiments,
        discovery_id,
        "discovery_experiment_missing_or_duplicated",
    )
    assert isinstance(discovery, Experiment)
    crash_envelope = _safe_result_envelope(
        discovery,
        "pwn_crash_evidence",
        "crash_result_envelope_invalid",
    )
    crash_evaluation = crash_envelope.get("evaluation")
    request = discovery.extra.get("pwn_crash_request")
    recipe = discovery.extra.get("pwn_crash_recipe")
    if (
        discovery.extra.get("engine_executor")
        != "pwn_crash_differential_v1"
        or discovery.status is not ExperimentStatus.KEPT
        or type(crash_evaluation) is not dict
        or crash_evaluation.get("verdict") != "CONFIRMED"
        or crash_evaluation.get("passed") is not True
        or crash_envelope.get("evaluation_sha256")
        != _sha256(crash_evaluation)
        or type(request) is not dict
        or type(recipe) is not dict
        or request.get("payload_artifact_id")
        != recipe.get("payload", {}).get("artifact_id")
        or request.get("payload_sha256")
        != recipe.get("payload", {}).get("sha256")
        or request.get("payload_size_bytes")
        != recipe.get("payload", {}).get("size_bytes")
        or crash_envelope.get("recipe_sha256")
        != recipe.get("recipe_sha256")
        or len(discovery.evidence_run_ids) != 6
        or len(discovery.evidence_receipt_ids) != 6
    ):
        raise PwnDependencyStateError("crash_state_not_exact_confirmed")
    return snapshot, discovery


def _proven_leak_for_snapshot(
    state: ChallengeState,
    snapshot_id: str,
) -> tuple[Experiment | None, PwnLeakResult | None]:
    proven: list[tuple[Experiment, PwnLeakResult]] = []
    for experiment in state.experiments:
        if (
            experiment.extra.get("engine_executor") != "pwn_leak_v1"
            or experiment.extra.get("baseline_experiment_id")
            != snapshot_id
            or experiment.status is not ExperimentStatus.COMPLETED
        ):
            continue
        try:
            envelope = _safe_result_envelope(
                experiment,
                "pwn_leak_evidence",
                "leak_result_envelope_invalid",
            )
            result = _parse_structural_pwn_leak_result(
                envelope.get("result")
            )
        except (PwnDependencyStateError, TypeError, ValueError):
            continue
        if result.status is not PwnLeakStatus.PROVEN:
            continue
        result_artifact_id = envelope.get("result_artifact_id")
        result_artifact = next(
            (
                value
                for value in state.artifacts
                if value.id == result_artifact_id
            ),
            None,
        )
        run_ids = experiment.extra.get("run_ids")
        receipt_ids = experiment.extra.get("receipt_ids")
        if (
            envelope.get("baseline_experiment_id") != snapshot_id
            or envelope.get("result_sha256") != result.evidence_sha256
            or envelope.get("plan_recipe_sha256")
            != result.plan_recipe_sha256
            or envelope.get("trusted_replay_expectation_sha256")
            != result.trusted_replay_expectation_sha256
            or type(run_ids) is not list
            or type(receipt_ids) is not list
            or len(run_ids) != PWN_LEAK_REPLAY_COUNT
            or len(receipt_ids) != PWN_LEAK_REPLAY_COUNT
            or envelope.get("run_ids") != run_ids
            or envelope.get("receipt_ids") != receipt_ids
            or experiment.evidence_run_ids != run_ids
            or experiment.evidence_receipt_ids != [receipt_ids[-1]]
            or not isinstance(result_artifact, ArtifactReference)
            or result_artifact.id not in experiment.artifact_ids
            or result_artifact.sha256 != result.evidence_sha256
        ):
            continue
        runs: list[RunReference] = []
        valid = True
        for ordinal, (run_id, commitment) in enumerate(
            zip(run_ids, result.replays, strict=True),
            start=1,
        ):
            matching = [
                run for run in state.runs if run.id == run_id
            ]
            if len(matching) != 1:
                valid = False
                break
            run = matching[0]
            replay = run.extra.get("pwn_leak_replay")
            receipt = (
                replay.get("receipt")
                if type(replay) is dict
                else None
            )
            if (
                run.role != "pwn_leak"
                or run.status not in _TERMINAL_RUN_STATUSES
                or type(replay) is not dict
                or replay.get("ordinal") != ordinal
                or type(receipt) is not dict
                or receipt.get("receipt_id") != receipt_ids[ordinal - 1]
                or receipt.get("run_id") != run_id
                or commitment.ordinal != ordinal
                or commitment.run_id != run_id
                or commitment.receipt_id != receipt_ids[ordinal - 1]
                or commitment.receipt_sha256 != _sha256(receipt)
            ):
                valid = False
                break
            runs.append(run)
        top_receipts = [
            receipt
            for receipt in state.receipts
            if receipt.id == receipt_ids[-1]
        ]
        if (
            not valid
            or len(top_receipts) != 1
            or top_receipts[0].run_id != run_ids[-1]
            or top_receipts[0].extra.get("pwn_leak_replay")
            != runs[-1].extra.get("pwn_leak_replay")
        ):
            continue
        proven.append((experiment, result))
    if not proven:
        return None, None
    proven.sort(key=lambda item: item[0].id)
    return proven[0]


def _parse_structural_pwn_leak_result(
    value: object,
) -> PwnLeakResult:
    """Parse a persisted leak result without granting physical authority.

    ``PwnLeakResult.from_dict`` deliberately refuses a PROVEN result unless
    the caller supplies an independently recomputed oracle result.  Graph
    construction has no sandbox handle, so this helper reconstructs only the
    typed, canonical state record.  The public dependency query performs the
    independent physical recomputation before it reports the L branch valid.
    """

    if type(value) is not dict:
        raise PwnDependencyStateError("leak_result_envelope_invalid")
    binding = value.get("binding")
    summary = value.get("summary")
    replays = value.get("replays")
    if (
        type(binding) is not dict
        or type(summary) is not dict
        or type(replays) is not list
    ):
        raise PwnDependencyStateError("leak_result_envelope_invalid")
    try:
        structural = PwnLeakResult(
            status=PwnLeakStatus(value["status"]),
            reason_code=value["reason_code"],
            plan_recipe_sha256=binding["plan_recipe_sha256"],
            trusted_replay_expectation_sha256=binding[
                "trusted_replay_expectation_sha256"
            ],
            disclosure_result_sha256=binding[
                "disclosure_result_sha256"
            ],
            source_manifest_sha256=binding[
                "source_manifest_sha256"
            ],
            source_sha256=binding["source_sha256"],
            source_size_bytes=binding["source_size_bytes"],
            baseline_payload_sha256=binding[
                "baseline_payload_sha256"
            ],
            baseline_payload_size_bytes=binding[
                "baseline_payload_size_bytes"
            ],
            candidate_byte_offset=binding["candidate_byte_offset"],
            candidate_hex_width=binding["candidate_hex_width"],
            replays=tuple(
                PwnLeakReplayCommitment.from_dict(item)
                for item in replays
            ),
            distinct_runtime_value_count=summary[
                "distinct_runtime_value_count"
            ],
            distinct_mapping_base_count=summary[
                "distinct_mapping_base_count"
            ],
            stable_map_identity_sha256=summary[
                "stable_map_identity_sha256"
            ],
            stable_relative_offset_sha256=summary[
                "stable_relative_offset_sha256"
            ],
        )
        return PwnLeakResult.from_dict(
            value,
            expected_result=structural,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise PwnDependencyStateError(
            "leak_result_envelope_invalid"
        ) from error


def _resolve_chain(
    state: ChallengeState,
    effect_experiment_id: str,
) -> _ResolvedChain:
    if (
        type(state) is not ChallengeState
        or state.category.strip().casefold() != "pwn"
    ):
        raise PwnDependencyStateError("dependency_graph_requires_pwn_state")
    validate_pwn_exploit_effect_state_graph(state)
    effect, effect_result, effect_binding = _effect_from_state(
        state,
        effect_experiment_id,
    )
    primitive, primitive_result = _primitive_from_state(
        state,
        effect_binding,
    )
    snapshot, discovery = _snapshot_and_discovery(
        state,
        primitive,
    )
    leak, leak_result = _proven_leak_for_snapshot(
        state,
        snapshot.id,
    )
    primitive_binding = primitive_result.to_dict()["binding"]
    effect_result_binding = effect_result.to_dict()["binding"]
    if (
        primitive_result.source_manifest_sha256
        != effect_result_binding["source_manifest_sha256"]
        or primitive_result.source_sha256
        != effect_result_binding["source_sha256"]
        or primitive_result.source_size_bytes
        != effect_result_binding["source_size_bytes"]
        or effect_result_binding["parent_ip_control_evidence_sha256"]
        != primitive_result.evidence_sha256
        or primitive_binding["controlled_offset"]
        != effect_result_binding["controlled_offset"]
        or primitive_binding["controlled_width_bytes"]
        != effect_result_binding["controlled_width_bytes"]
    ):
        raise PwnDependencyStateError(
            "primitive_effect_target_binding_changed"
        )
    return _ResolvedChain(
        discovery=discovery,
        snapshot=snapshot,
        leak=leak,
        primitive=primitive,
        effect=effect,
        primitive_result=primitive_result,
        effect_result=effect_result,
        effect_binding=effect_binding,
        leak_result=leak_result,
    )


def _run_revisions(
    state: ChallengeState,
    experiment: Experiment,
) -> list[int]:
    wanted = set(experiment.evidence_run_ids)
    if experiment.extra.get("engine_executor") == "pwn_leak_v1":
        raw = experiment.extra.get("run_ids")
        if type(raw) is list:
            wanted.update(
                item for item in raw if type(item) is str
            )
    revisions = sorted(
        {
            run.base_revision
            for run in state.runs
            if run.id in wanted
        }
    )
    if not revisions:
        raise PwnDependencyStateError(
            f"experiment_run_revision_missing:{experiment.id}"
        )
    return revisions


def _node_artifact_pointers(
    state: ChallengeState,
    experiment: Experiment,
    *,
    maximum: int = 8,
) -> list[dict[str, object]]:
    artifacts = {item.id: item for item in state.artifacts}
    pointers: list[dict[str, object]] = []
    for artifact_id in experiment.artifact_ids:
        artifact = artifacts.get(artifact_id)
        if artifact is None:
            raise PwnDependencyStateError(
                f"node_artifact_missing:{experiment.id}"
            )
        if len(pointers) >= maximum:
            break
        pointers.append(
            {
                "artifact_id": artifact.id,
                "path": artifact.path,
                "sha256": artifact.sha256,
                "size_bytes": artifact.size,
            }
        )
    return pointers


def _support_closure(
    state: ChallengeState,
    chain: _ResolvedChain,
) -> dict[str, object]:
    selected_experiments = [
        chain.discovery,
        chain.snapshot,
        *([chain.leak] if chain.leak is not None else []),
        chain.primitive,
        chain.effect,
    ]
    experiment_ids = {item.id for item in selected_experiments}
    run_ids: set[str] = set()
    receipt_ids: set[str] = set()
    artifact_ids: set[str] = set()
    fact_ids: set[str] = set()
    hypothesis_ids: set[str] = set()
    for experiment in selected_experiments:
        run_ids.update(experiment.evidence_run_ids)
        receipt_ids.update(experiment.evidence_receipt_ids)
        artifact_ids.update(experiment.artifact_ids)
        fact_ids.update(experiment.evidence_fact_ids)
        hypothesis_ids.update(experiment.hypothesis_ids)
        if (
            experiment is chain.discovery
            and experiment.source_run_id is not None
        ):
            run_ids.add(experiment.source_run_id)
        if experiment.extra.get("engine_executor") == "pwn_leak_v1":
            for key, destination in (
                ("run_ids", run_ids),
                ("receipt_ids", receipt_ids),
            ):
                values = experiment.extra.get(key)
                if type(values) is list:
                    destination.update(
                        item for item in values if type(item) is str
                    )
    for receipt in state.receipts:
        if receipt.run_id in run_ids:
            receipt_ids.add(receipt.id)
            for artifact_id in (
                receipt.stdout_artifact_id,
                receipt.stderr_artifact_id,
            ):
                if artifact_id is not None:
                    artifact_ids.add(artifact_id)
            for key in (
                "target_stdout_artifact_id",
                "target_stderr_artifact_id",
            ):
                value = receipt.extra.get(key)
                if type(value) is str:
                    artifact_ids.add(value)
    for artifact in state.artifacts:
        if artifact.source_run_id in run_ids:
            artifact_ids.add(artifact.id)
    for fact in state.facts:
        if (
            fact.id in fact_ids
            or fact.source_run_id in run_ids
            or fact.artifact_id in artifact_ids
        ):
            fact_ids.add(fact.id)
    progress_ids = {
        marker.id
        for marker in state.progress_markers
        if (
            marker.run_id in run_ids
            or not set(marker.artifact_ids).isdisjoint(artifact_ids)
        )
    }
    indexes = {
        "experiments": {item.id: item for item in state.experiments},
        "runs": {item.id: item for item in state.runs},
        "receipts": {item.id: item for item in state.receipts},
        "artifacts": {item.id: item for item in state.artifacts},
        "hypotheses": {item.id: item for item in state.hypotheses},
        "facts": {item.id: item for item in state.facts},
        "progress": {
            item.id: item for item in state.progress_markers
        },
    }
    selected = {
        "experiments": experiment_ids,
        "runs": run_ids,
        # Some leak replay receipts are intentionally embedded only in the
        # exact terminal run record.  Top-level receipt commitments include
        # exactly the receipts that actually exist in canonical state.
        "receipts": receipt_ids.intersection(indexes["receipts"]),
        "artifacts": artifact_ids,
        "hypotheses": hypothesis_ids,
        "facts": fact_ids,
        "progress": progress_ids,
    }
    if any(
        len(ids) > PWN_DEPENDENCY_STATE_MAX_OBJECTS
        for ids in selected.values()
    ):
        raise PwnDependencyStateError(
            "dependency_support_closure_too_large"
        )
    missing = {
        kind: sorted(ids.difference(indexes[kind]))
        for kind, ids in selected.items()
        if ids.difference(indexes[kind])
    }
    if missing:
        raise PwnDependencyStateError(
            "dependency_support_closure_orphaned"
        )
    experiment_records = [
        {
            "id": item.id,
            "record_sha256": _sha256(_experiment_record(item)),
            "status": item.status.value,
        }
        for item in (
            indexes["experiments"][identifier]
            for identifier in sorted(selected["experiments"])
        )
    ]
    run_records = [
        {
            "base_revision": item.base_revision,
            "id": item.id,
            "record_sha256": _sha256(_run_record(item)),
            "status": item.status.value,
        }
        for item in (
            indexes["runs"][identifier]
            for identifier in sorted(selected["runs"])
        )
    ]
    receipt_records = [
        {
            "id": item.id,
            "record_sha256": _sha256(_receipt_record(item)),
            "run_id": item.run_id,
        }
        for item in (
            indexes["receipts"][identifier]
            for identifier in sorted(selected["receipts"])
        )
    ]
    artifact_records = [
        {
            "id": item.id,
            "media_type": item.media_type,
            "path": item.path,
            "record_sha256": _sha256(_artifact_record(item)),
            "sha256": item.sha256,
            "size_bytes": item.size,
            "source_run_id": item.source_run_id,
        }
        for item in (
            indexes["artifacts"][identifier]
            for identifier in sorted(selected["artifacts"])
        )
    ]
    hypothesis_records = [
        {
            "id": item.id,
            "record_sha256": _sha256(_hypothesis_record(item)),
            "status": item.status.value,
        }
        for item in (
            indexes["hypotheses"][identifier]
            for identifier in sorted(selected["hypotheses"])
        )
    ]
    fact_records = [
        {
            "id": item.id,
            "record_sha256": _sha256(
                _fact_record(
                    item,
                    challenge_id=state.challenge_id,
                )
            ),
        }
        for item in (
            indexes["facts"][identifier]
            for identifier in sorted(selected["facts"])
        )
    ]
    progress_records = [
        {
            "id": item.id,
            "record_sha256": _sha256(_progress_record(item)),
        }
        for item in (
            indexes["progress"][identifier]
            for identifier in sorted(selected["progress"])
        )
    ]
    embedded_receipts: list[dict[str, object]] = []
    if chain.leak is not None:
        raw_run_ids = chain.leak.extra.get("run_ids")
        assert isinstance(raw_run_ids, list)
        runs = indexes["runs"]
        for ordinal, run_id in enumerate(raw_run_ids, start=1):
            run = runs[run_id]
            replay = run.extra.get("pwn_leak_replay")
            assert isinstance(replay, dict)
            receipt = replay.get("receipt")
            assert isinstance(receipt, dict)
            embedded_receipts.append(
                {
                    "ordinal": ordinal,
                    "receipt_id": receipt["receipt_id"],
                    "receipt_sha256": _sha256(receipt),
                    "run_id": run_id,
                }
            )
    return {
        "artifacts": artifact_records,
        "embedded_receipts": embedded_receipts,
        "experiments": experiment_records,
        "facts": fact_records,
        "hypotheses": hypothesis_records,
        "progress": progress_records,
        "receipts": receipt_records,
        "runs": run_records,
    }


def build_pwn_dependency_state_graph(
    state: ChallengeState,
    *,
    effect_experiment_id: str,
    source_state_revision: int,
    committed_state_revision: int,
) -> dict[str, object]:
    """Build one exact final dependency graph from canonical state objects."""

    if (
        type(effect_experiment_id) is not str
        or not effect_experiment_id
        or type(source_state_revision) is not int
        or source_state_revision < 0
        or type(committed_state_revision) is not int
        or committed_state_revision != source_state_revision + 1
        or not (
            state.revision == source_state_revision
            or state.revision >= committed_state_revision
        )
    ):
        raise PwnDependencyStateError(
            "dependency_state_revision_commitment_invalid"
        )
    chain = _resolve_chain(state, effect_experiment_id)
    effect_result = chain.effect_result.to_dict()
    effect_result_binding = effect_result["binding"]
    assert isinstance(effect_result_binding, dict)
    effect_experiment_binding = chain.effect_binding["experiment"]
    effect_chronology = chain.effect_binding["chronology"]
    effect_state_ids = chain.effect_binding["state_ids"]
    effect_replays = chain.effect_binding["replays"]
    assert isinstance(effect_experiment_binding, dict)
    assert isinstance(effect_chronology, dict)
    assert isinstance(effect_state_ids, dict)
    assert isinstance(effect_replays, list)
    if (
        type(effect_chronology.get("preissue_revision")) is not int
        or source_state_revision
        != effect_chronology["preissue_revision"] + 1
    ):
        raise PwnDependencyStateError(
            "dependency_source_revision_not_effect_final_base"
        )
    graph_id = effect_state_ids["attempt_id"]
    if type(graph_id) is not str:
        raise PwnDependencyStateError("dependency_graph_id_invalid")
    crash_envelope = chain.discovery.result["pwn_crash_evidence"]
    snapshot_envelope = chain.snapshot.result[
        "pwn_runtime_snapshot_evidence"
    ]
    assert isinstance(crash_envelope, dict)
    assert isinstance(snapshot_envelope, dict)
    crash_request = chain.discovery.extra["pwn_crash_request"]
    crash_recipe = chain.discovery.extra["pwn_crash_recipe"]
    assert isinstance(crash_request, dict)
    assert isinstance(crash_recipe, dict)
    payload_binding = crash_recipe["payload"]
    source_binding = crash_recipe["source"]
    assert isinstance(payload_binding, dict)
    assert isinstance(source_binding, dict)
    source_locator = source_binding["locator"]
    first_replay = effect_replays[0]
    assert isinstance(first_replay, dict)
    first_request = first_replay["request"]
    assert isinstance(first_request, dict)
    runtime = first_request["runtime"]
    assert isinstance(runtime, dict)
    static_target = {
        "configuration_epoch": state.configuration_epoch,
        "image_digest": runtime["image_digest"],
        "source_locator": source_locator,
        "source_manifest_sha256": (
            effect_result_binding["source_manifest_sha256"]
        ),
        "source_sha256": effect_result_binding["source_sha256"],
        "source_size_bytes": effect_result_binding["source_size_bytes"],
    }
    if chain.leak is not None:
        assert chain.leak_result is not None
        address_node: dict[str, object] = {
            "artifact_pointers": _node_artifact_pointers(
                state,
                chain.leak,
            ),
            "branch": "LEAK_PROVEN",
            "experiment_id": chain.leak.id,
            "result_sha256": chain.leak_result.evidence_sha256,
            "revision_commitments": {
                "expectation_source_state_revision": chain.leak.extra[
                    "expectation_source_state_revision"
                ],
                "run_base_revisions": _run_revisions(
                    state,
                    chain.leak,
                ),
            },
            "status": "PROVEN",
        }
        branch = "LEAK_PROVEN"
        evidence_edges = [
            {
                "from": "V",
                "kind": "runtime_snapshot_support",
                "to": "L",
            }
        ]
        gate_route = ["D", "V", "L", "P", "E"]
        dependency_claims = {
            **_DEPENDENCY_CLAIMS_FALSE,
            "leak_proven": True,
        }
    else:
        # This certificate is deliberately post-effect.  The static target
        # only scopes the judgement; it is not evidence that a leak is
        # unnecessary.  The observed exact P and E nodes are the witnesses.
        address_node = {
            "advisory_authority_used": False,
            "branch": "DEPENDENCY_SCOPED_NOT_APPLICABLE",
            "certificate_scope": {
                "effect_attempt_id": graph_id,
                "effect_experiment_id": chain.effect.id,
                "primitive_experiment_id": chain.primitive.id,
                "static_target_sha256": _sha256(static_target),
            },
            "decision_phase": "retrospective_after_exact_effect",
            "leak_dependency_ids": [],
            "negative_dependency_closure": {
                "effect_parent_ip_control_evidence_sha256": (
                    effect_result_binding[
                        "parent_ip_control_evidence_sha256"
                    ]
                ),
                "effect_plan_derivation_algorithm": (
                    chain.effect_binding["journal"]["plan"][
                        "derivation_algorithm"
                    ]
                ),
                "effect_plan_recipe_sha256": (
                    chain.effect_binding["journal"]["plan"][
                        "recipe_sha256"
                    ]
                ),
                "explicit_leak_dependency_field_present": False,
                "resolution_scope": "observed_effect_attempt_only",
            },
            "non_pie_inference_used": False,
            "status": "PROVEN",
            "witnesses": {
                "effect_result_sha256": chain.effect_result.evidence_sha256,
                "primitive_result_sha256": (
                    chain.primitive_result.evidence_sha256
                ),
            },
        }
        branch = "DEPENDENCY_SCOPED_NOT_APPLICABLE"
        evidence_edges = [
            {
                "from": "P",
                "kind": "retrospective_na_witness",
                "to": "N/A",
            },
            {
                "from": "E",
                "kind": "retrospective_na_witness",
                "to": "N/A",
            },
        ]
        gate_route = ["D", "V", "N/A", "P", "E"]
        dependency_claims = copy.deepcopy(_DEPENDENCY_CLAIMS_FALSE)
    primitive_envelope = chain.primitive.result[
        "pwn_ip_control_evidence"
    ]
    assert isinstance(primitive_envelope, dict)
    graph = {
        "advisory": {
            "authority_used": False,
            "contract_fingerprint": (
                PWN_LEAK_REQUIREMENT_V1_CONTRACT_FINGERPRINT
            ),
            "contract_id": PWN_LEAK_REQUIREMENT_V1_CONTRACT_ID,
            "role": "advisory_only",
        },
        "authorities": copy.deepcopy(_AUTHORITIES),
        "branch": branch,
        "committed_state_revision": committed_state_revision,
        "dependency_claims": dependency_claims,
        "evidence_edges": evidence_edges,
        "gate_edges": [
            {
                "from": gate_route[index],
                "kind": "gate_dependency",
                "to": gate_route[index + 1],
            }
            for index in range(len(gate_route) - 1)
        ],
        "gate_route": gate_route,
        "graph_id": graph_id,
        "identity": {
            "category": state.category,
            "challenge_id": state.challenge_id,
            "contest_id": state.contest_id,
        },
        "nodes": {
            "D": {
                "artifact_pointers": _node_artifact_pointers(
                    state,
                    chain.discovery,
                ),
                "experiment_id": chain.discovery.id,
                "hypothesis_ids": list(
                    chain.discovery.hypothesis_ids
                ),
                "payload_artifact_id": (
                    crash_request["payload_artifact_id"]
                ),
                "payload_sha256": payload_binding["sha256"],
                "payload_size_bytes": payload_binding["size_bytes"],
                "source_builder_run_id": (
                    crash_request["source_builder_run_id"]
                ),
                "status": "BOUND",
            },
            "V": {
                "artifact_pointers": _node_artifact_pointers(
                    state,
                    chain.discovery,
                ),
                "evaluation_sha256": (
                    crash_envelope["evaluation_sha256"]
                ),
                "experiment_id": chain.discovery.id,
                "receipt_ids": list(
                    chain.discovery.evidence_receipt_ids
                ),
                "revision_commitments": {
                    "run_base_revisions": _run_revisions(
                        state,
                        chain.discovery,
                    )
                },
                "status": "CONFIRMED",
            },
            "address_resolution": address_node,
            "P": {
                "artifact_pointers": _node_artifact_pointers(
                    state,
                    chain.primitive,
                ),
                "controlled_offset": (
                    chain.primitive_result.controlled_offset
                ),
                "controlled_width_bytes": 8,
                "experiment_id": chain.primitive.id,
                "receipt_ids": list(
                    chain.primitive.evidence_receipt_ids
                ),
                "result_sha256": (
                    chain.primitive_result.evidence_sha256
                ),
                "revision_commitments": {
                    "run_base_revisions": _run_revisions(
                        state,
                        chain.primitive,
                    )
                },
                "status": "PROVEN",
            },
            "E": {
                "artifact_pointers": _node_artifact_pointers(
                    state,
                    chain.effect,
                ),
                "effect_attempt_id": graph_id,
                "experiment_id": chain.effect.id,
                "receipt_ids": list(
                    chain.effect.evidence_receipt_ids
                ),
                "result_sha256": chain.effect_result.evidence_sha256,
                "revision_commitments": {
                    "effect_base_revision": chain.effect_binding[
                        "base_revision"
                    ],
                    "preissue_revision": effect_chronology[
                        "preissue_revision"
                    ],
                    "run_base_revisions": _run_revisions(
                        state,
                        chain.effect,
                    ),
                },
                "status": "PROVEN",
            },
        },
        "protocol": PWN_DEPENDENCY_STATE_PROTOCOL,
        "runtime_observation": {
            "artifact_pointers": _node_artifact_pointers(
                state,
                chain.snapshot,
            ),
            "evaluation_sha256": (
                snapshot_envelope["evaluation_sha256"]
            ),
            "experiment_id": chain.snapshot.id,
            "revision_commitments": {
                "disclosure_evaluation_source_state_revision": (
                    chain.snapshot.extra["pwn_disclosure"][
                        "evaluation_source_state_revision"
                    ]
                ),
                "disclosure_expectation_source_state_revision": (
                    chain.snapshot.extra["pwn_disclosure"][
                        "expectation_source_state_revision"
                    ]
                ),
                "run_base_revisions": _run_revisions(
                    state,
                    chain.snapshot,
                ),
            },
            "status": "CAPTURED",
            "supports": ["V", branch, "P"],
        },
        "schema_version": PWN_DEPENDENCY_STATE_SCHEMA_VERSION,
        "source_state_revision": source_state_revision,
        "static_target": static_target,
        "support_closure": _support_closure(state, chain),
    }
    _validate_graph_shape(graph)
    _canonical_bytes(graph)
    return graph


def _validate_graph_shape(graph: object) -> dict[str, object]:
    graph = _exact_dict(
        graph,
        {
            "advisory",
            "authorities",
            "branch",
            "committed_state_revision",
            "dependency_claims",
            "evidence_edges",
            "gate_edges",
            "gate_route",
            "graph_id",
            "identity",
            "nodes",
            "protocol",
            "runtime_observation",
            "schema_version",
            "source_state_revision",
            "static_target",
            "support_closure",
        },
        "dependency_graph_schema_invalid",
    )
    source_revision = graph["source_state_revision"]
    committed_revision = graph["committed_state_revision"]
    if (
        graph["protocol"] != PWN_DEPENDENCY_STATE_PROTOCOL
        or graph["schema_version"]
        != PWN_DEPENDENCY_STATE_SCHEMA_VERSION
        or graph["authorities"] != _AUTHORITIES
        or type(graph["dependency_claims"]) is not dict
        or graph["dependency_claims"]
        != {
            **_DEPENDENCY_CLAIMS_FALSE,
            "leak_proven": graph["branch"] == "LEAK_PROVEN",
        }
        or type(source_revision) is not int
        or type(committed_revision) is not int
        or committed_revision != source_revision + 1
        or graph["branch"]
        not in {
            "LEAK_PROVEN",
            "DEPENDENCY_SCOPED_NOT_APPLICABLE",
        }
        or type(graph["graph_id"]) is not str
        or not graph["graph_id"]
    ):
        raise PwnDependencyStateError(
            "dependency_graph_semantics_invalid"
        )
    nodes = graph["nodes"]
    if type(nodes) is not dict or set(nodes) != {
        "D",
        "V",
        "address_resolution",
        "P",
        "E",
    }:
        raise PwnDependencyStateError("dependency_graph_nodes_invalid")
    address = nodes["address_resolution"]
    if type(address) is not dict:
        raise PwnDependencyStateError(
            "dependency_address_node_invalid"
        )
    route = graph["gate_route"]
    expected_route = (
        ["D", "V", "L", "P", "E"]
        if graph["branch"] == "LEAK_PROVEN"
        else ["D", "V", "N/A", "P", "E"]
    )
    if route != expected_route:
        raise PwnDependencyStateError("dependency_gate_route_invalid")
    advisory = graph["advisory"]
    if (
        type(advisory) is not dict
        or advisory.get("authority_used") is not False
        or advisory.get("role") != "advisory_only"
    ):
        raise PwnDependencyStateError(
            "leak_requirement_advisory_acquired_authority"
        )
    if graph["branch"] == "DEPENDENCY_SCOPED_NOT_APPLICABLE":
        if (
            address.get("branch")
            != "DEPENDENCY_SCOPED_NOT_APPLICABLE"
            or address.get("advisory_authority_used") is not False
            or address.get("non_pie_inference_used") is not False
            or address.get("decision_phase")
            != "retrospective_after_exact_effect"
            or address.get("leak_dependency_ids") != []
            or set(address.get("negative_dependency_closure", {}))
            != {
                "effect_parent_ip_control_evidence_sha256",
                "effect_plan_derivation_algorithm",
                "effect_plan_recipe_sha256",
                "explicit_leak_dependency_field_present",
                "resolution_scope",
            }
            or address["negative_dependency_closure"].get(
                "explicit_leak_dependency_field_present"
            )
            is not False
            or address["negative_dependency_closure"].get(
                "resolution_scope"
            )
            != "observed_effect_attempt_only"
            or set(address.get("witnesses", {}))
            != {
                "effect_result_sha256",
                "primitive_result_sha256",
            }
        ):
            raise PwnDependencyStateError(
                "dependency_scoped_na_invalid"
            )
    elif (
        address.get("branch") != "LEAK_PROVEN"
        or address.get("status") != "PROVEN"
        or type(address.get("experiment_id")) is not str
    ):
        raise PwnDependencyStateError(
            "dependency_leak_node_invalid"
        )
    return graph


def _production_final_effect_ids(
    state: ChallengeState,
) -> set[str]:
    selected: set[str] = set()
    for experiment in state.experiments:
        if (
            experiment.extra.get("engine_executor")
            != PWN_EXPLOIT_EFFECT_STATE_EXECUTOR
            or experiment.status is not ExperimentStatus.COMPLETED
        ):
            continue
        marker = experiment.extra.get("pwn_exploit_effect_state")
        if type(marker) is not dict:
            continue
        binding = marker.get("binding")
        experiment_binding = (
            binding.get("experiment")
            if type(binding) is dict
            else None
        )
        result_mapping = (
            binding.get("result")
            if type(binding) is dict
            else None
        )
        parent_id = (
            experiment_binding.get("parent_experiment_id")
            if type(experiment_binding) is dict
            else None
        )
        if (
            type(parent_id) is str
            and experiment.id
            == pwn_exploit_effect_child_experiment_id(parent_id)
            and type(result_mapping) is dict
            and result_mapping.get("status")
            == PwnExploitEffectStatus.PROVEN.value
        ):
            selected.add(experiment.id)
    return selected


def pwn_dependency_state_graph_errors(
    state: ChallengeState,
) -> list[str]:
    """Return exact graph errors without mutating canonical state."""

    if type(state) is not ChallengeState:
        return ["Pwn dependency graph requires exact ChallengeState"]
    journal = state.extra.get(PWN_DEPENDENCY_STATE_JOURNAL_KEY)
    required_effect_ids = _production_final_effect_ids(state)
    if journal is None:
        if required_effect_ids:
            return [
                "proven production Pwn effect is missing dependency graph"
            ]
        return []
    if type(journal) is not dict:
        return ["Pwn dependency graph journal must be an object"]
    errors: list[str] = []
    bound_effect_ids: set[str] = set()
    bound_graph_ids: set[str] = set()
    for graph_id, wrapper_value in journal.items():
        label = f"Pwn dependency graph {graph_id}"
        try:
            if type(graph_id) is not str or not graph_id:
                raise PwnDependencyStateError(
                    "dependency_graph_key_invalid"
                )
            wrapper = _exact_dict(
                wrapper_value,
                {
                    "effect_experiment_id",
                    "graph",
                    "graph_sha256",
                    "protocol",
                    "schema_version",
                },
                "dependency_graph_wrapper_invalid",
            )
            graph = _validate_graph_shape(wrapper["graph"])
            effect_id = wrapper["effect_experiment_id"]
            if (
                wrapper["protocol"] != PWN_DEPENDENCY_STATE_PROTOCOL
                or wrapper["schema_version"]
                != PWN_DEPENDENCY_STATE_SCHEMA_VERSION
                or graph["graph_id"] != graph_id
                or wrapper["graph_sha256"] != _sha256(graph)
                or type(effect_id) is not str
                or effect_id in bound_effect_ids
                or graph_id in bound_graph_ids
            ):
                raise PwnDependencyStateError(
                    "dependency_graph_wrapper_binding_invalid"
                )
            source_revision = graph["source_state_revision"]
            committed_revision = graph["committed_state_revision"]
            assert isinstance(source_revision, int)
            assert isinstance(committed_revision, int)
            if not (
                state.revision == source_revision
                or state.revision >= committed_revision
            ):
                raise PwnDependencyStateError(
                    "dependency_graph_state_revision_stale"
                )
            if graph["identity"] != {
                "category": state.category,
                "challenge_id": state.challenge_id,
                "contest_id": state.contest_id,
            }:
                raise PwnDependencyStateError(
                    "dependency_graph_identity_rebound"
                )
            static_target = graph["static_target"]
            if (
                type(static_target) is not dict
                or static_target.get("configuration_epoch")
                != state.configuration_epoch
                or state.metadata.get("source_manifest_sha256")
                != static_target.get("source_manifest_sha256")
            ):
                raise PwnDependencyStateError(
                    "dependency_graph_static_target_stale"
                )
            expected = build_pwn_dependency_state_graph(
                state,
                effect_experiment_id=effect_id,
                source_state_revision=source_revision,
                committed_state_revision=committed_revision,
            )
            if expected != graph:
                raise PwnDependencyStateError(
                    "dependency_graph_upstream_rebound"
                )
            bound_effect_ids.add(effect_id)
            bound_graph_ids.add(graph_id)
        except (
            AssertionError,
            KeyError,
            TypeError,
            ValueError,
            PwnDependencyStateError,
        ) as error:
            errors.append(f"{label} is invalid: {error}")
    for effect_id in sorted(required_effect_ids - bound_effect_ids):
        errors.append(
            f"proven production Pwn effect {effect_id} is missing "
            "dependency graph"
        )
    for effect_id in sorted(bound_effect_ids - required_effect_ids):
        errors.append(
            f"orphan Pwn dependency graph for effect {effect_id}"
        )
    return errors


def validate_pwn_dependency_state_graph(
    state: ChallengeState,
) -> None:
    """Raise on the first missing, stale, rebound, or forged graph."""

    errors = pwn_dependency_state_graph_errors(state)
    if errors:
        raise PwnDependencyStateError(errors[0])


def append_pwn_dependency_state_graph(
    state: ChallengeState,
    *,
    effect_experiment_id: str,
    source_state_revision: int,
    committed_state_revision: int,
) -> dict[str, object]:
    """Append one graph to an engine-owned proposed state.

    The caller must invoke this inside the same ``StateStore.update`` mutator
    that installs the final effect projection.  Workers and models never call
    this function.
    """

    graph = build_pwn_dependency_state_graph(
        state,
        effect_experiment_id=effect_experiment_id,
        source_state_revision=source_state_revision,
        committed_state_revision=committed_state_revision,
    )
    graph_id = graph["graph_id"]
    assert isinstance(graph_id, str)
    root = state.extra.setdefault(
        PWN_DEPENDENCY_STATE_JOURNAL_KEY,
        {},
    )
    if type(root) is not dict or graph_id in root:
        raise PwnDependencyStateError(
            "dependency_graph_journal_collision"
        )
    wrapper = {
        "effect_experiment_id": effect_experiment_id,
        "graph": copy.deepcopy(graph),
        "graph_sha256": _sha256(graph),
        "protocol": PWN_DEPENDENCY_STATE_PROTOCOL,
        "schema_version": PWN_DEPENDENCY_STATE_SCHEMA_VERSION,
    }
    root[graph_id] = wrapper
    validate_pwn_dependency_state_graph(state)
    return copy.deepcopy(wrapper)


def _latest_graph_wrapper(
    state: ChallengeState,
    *,
    graph_id: str | None = None,
) -> tuple[str, dict[str, object]] | None:
    root = state.extra.get(PWN_DEPENDENCY_STATE_JOURNAL_KEY)
    if type(root) is not dict or not root:
        return None
    if graph_id is not None:
        wrapper = root.get(graph_id)
        if type(wrapper) is not dict:
            return None
        return graph_id, wrapper
    selected_id = sorted(root)[-1]
    wrapper = root[selected_id]
    if type(wrapper) is not dict:
        return None
    return selected_id, wrapper


def project_pwn_dependency_context(
    state: ChallengeState,
    *,
    graph_id: str | None = None,
    compact: bool = False,
) -> dict[str, object] | None:
    """Return one bounded raw-free complete or incomplete chain capsule."""

    selected = _latest_graph_wrapper(state, graph_id=graph_id)
    if selected is not None:
        validate_pwn_dependency_state_graph(state)
        selected_id, wrapper = selected
        graph = wrapper["graph"]
        assert isinstance(graph, dict)
        nodes = graph["nodes"]
        assert isinstance(nodes, dict)
        result: dict[str, object] = {
            "branch": graph["branch"],
            "completed_gates": list(graph["gate_route"]),
            "current_gate": "COMPLETE",
            "graph_id": selected_id,
            "graph_pointer": (
                "state.json#/extra/"
                f"{PWN_DEPENDENCY_STATE_JOURNAL_KEY}/{selected_id}"
            ),
            "graph_sha256": wrapper["graph_sha256"],
            "protocol": PWN_DEPENDENCY_CONTEXT_PROTOCOL,
            "raw_output_included": False,
            "source_state_revision": graph[
                "source_state_revision"
            ],
            "status": "COMPLETE",
        }
        if not compact:
            result["nodes"] = {
                key: {
                    "experiment_id": value.get("experiment_id"),
                    "result_sha256": value.get(
                        "result_sha256",
                        value.get("evaluation_sha256"),
                    ),
                    "status": value.get("status"),
                }
                for key, value in nodes.items()
                if type(value) is dict
            }
            result["static_target"] = copy.deepcopy(
                graph["static_target"]
            )
        _canonical_bytes(result, maximum_bytes=32 * 1024)
        return result
    if state.category.strip().casefold() != "pwn":
        return None
    completed: list[str] = []
    current = "D"
    failure_codes: list[str] = []
    crash = next(
        (
            item
            for item in reversed(state.experiments)
            if item.extra.get("engine_executor")
            == "pwn_crash_differential_v1"
            and item.status is ExperimentStatus.KEPT
        ),
        None,
    )
    if crash is not None:
        completed.extend(["D", "V"])
        current = "P"
    primitive = next(
        (
            item
            for item in reversed(state.experiments)
            if item.extra.get("engine_executor")
            == "pwn_ip_control_v1"
            and item.status is ExperimentStatus.COMPLETED
        ),
        None,
    )
    if primitive is not None:
        completed.append("P")
        current = "E"
        failure_codes.append("address_resolution_pending_retrospective_E")
    preissued_effect = next(
        (
            item
            for item in reversed(state.experiments)
            if item.extra.get("engine_executor")
            == PWN_EXPLOIT_EFFECT_STATE_EXECUTOR
        ),
        None,
    )
    if preissued_effect is not None:
        current = "E"
        if preissued_effect.status is ExperimentStatus.REGISTERED:
            failure_codes.append("effect_preissued_not_final")
        elif preissued_effect.status is ExperimentStatus.FAILED:
            failure_codes.append("effect_exact_replay_rejected")
        elif preissued_effect.status is ExperimentStatus.COMPLETED:
            failure_codes.append("effect_dependency_graph_missing")
    if not failure_codes:
        failure_codes.append(f"awaiting_exact_{current.lower()}_evidence")
    result = {
        "completed_gates": completed,
        "current_gate": current,
        "failure_codes": failure_codes[:3],
        "graph_pointer": (
            "state.json#/extra/"
            f"{PWN_DEPENDENCY_STATE_JOURNAL_KEY}"
        ),
        "protocol": PWN_DEPENDENCY_CONTEXT_PROTOCOL,
        "raw_output_included": False,
        "state_revision": state.revision,
        "status": "INCOMPLETE",
    }
    _canonical_bytes(result, maximum_bytes=16 * 1024)
    return result


def project_pwn_dependency_failure_capsule(
    state: ChallengeState,
) -> dict[str, object] | None:
    """Return the same bounded machine projection under a capsule kind."""

    projected = project_pwn_dependency_context(state, compact=True)
    if projected is None:
        return None
    capsule = {
        "kind": "pwn_dependency_failure_capsule",
        **projected,
    }
    _canonical_bytes(capsule, maximum_bytes=16 * 1024)
    return capsule


def pwn_dependency_artifact_commitments(
    state: ChallengeState,
    *,
    graph_id: str | None = None,
) -> tuple[dict[str, object], ...]:
    """Expose exact artifact pointers for a public engine byte revalidation."""

    selected = _latest_graph_wrapper(state, graph_id=graph_id)
    if selected is None:
        raise PwnDependencyStateError("dependency_graph_not_found")
    validate_pwn_dependency_state_graph(state)
    graph = selected[1]["graph"]
    assert isinstance(graph, dict)
    closure = graph["support_closure"]
    assert isinstance(closure, dict)
    artifacts = closure["artifacts"]
    assert isinstance(artifacts, list)
    total = sum(
        int(item["size_bytes"])
        for item in artifacts
        if isinstance(item, dict)
        and isinstance(item.get("size_bytes"), int)
    )
    if total > PWN_DEPENDENCY_STATE_MAX_ARTIFACT_BYTES:
        raise PwnDependencyStateError(
            "dependency_artifact_validation_bound_exceeded"
        )
    return tuple(copy.deepcopy(artifacts))


def verify_pwn_dependency_artifact_bytes(
    challenge_state_root: Path,
    state: ChallengeState,
    *,
    graph_id: str | None = None,
) -> dict[str, object]:
    """Descriptor-reread every committed artifact without returning bytes."""

    if not isinstance(challenge_state_root, Path) or not challenge_state_root.is_dir():
        raise PwnDependencyStateError(
            "dependency_artifact_root_invalid"
        )
    commitments = pwn_dependency_artifact_commitments(
        state,
        graph_id=graph_id,
    )
    artifacts = {item.id: item for item in state.artifacts}
    total = 0
    digest = hashlib.sha256()
    for commitment in commitments:
        artifact_id = commitment.get("id")
        artifact = artifacts.get(artifact_id)
        if (
            type(artifact_id) is not str
            or artifact is None
            or commitment
            != {
                "id": artifact.id,
                "media_type": artifact.media_type,
                "path": artifact.path,
                "record_sha256": _sha256(
                    _artifact_record(artifact)
                ),
                "sha256": artifact.sha256,
                "size_bytes": artifact.size,
                "source_run_id": artifact.source_run_id,
            }
            or _SAFE_PATH.fullmatch(artifact.path) is None
            or type(artifact.size) is not int
            or artifact.size < 0
        ):
            raise PwnDependencyStateError(
                "dependency_artifact_commitment_rebound"
            )
        total += artifact.size
        if total > PWN_DEPENDENCY_STATE_MAX_ARTIFACT_BYTES:
            raise PwnDependencyStateError(
                "dependency_artifact_validation_bound_exceeded"
            )
        try:
            payload = read_bounded_regular(
                challenge_state_root,
                artifact.path,
                maximum_bytes=max(1, artifact.size),
                expected_sha256=artifact.sha256,
                expected_size=artifact.size,
            )
        except (OSError, SafeFileError, ValueError) as error:
            raise PwnDependencyStateError(
                f"dependency_artifact_bytes_changed:{artifact.id}"
            ) from error
        if len(payload) != artifact.size:
            raise PwnDependencyStateError(
                f"dependency_artifact_bytes_changed:{artifact.id}"
            )
        digest.update(artifact.id.encode("utf-8"))
        digest.update(b"\0")
        digest.update(artifact.sha256.encode("ascii"))
        digest.update(b"\0")
        digest.update(str(artifact.size).encode("ascii"))
        digest.update(b"\n")
    return {
        "aggregate_commitment_sha256": digest.hexdigest(),
        "artifact_count": len(commitments),
        "descriptor_reread": True,
        "nofollow_required": True,
        "raw_output_returned": False,
        "total_bytes": total,
    }


def verify_pwn_dependency_static_target(
    challenge_input_root: Path,
    state: ChallengeState,
    *,
    graph_id: str | None = None,
) -> dict[str, object]:
    """Reinventory immutable input and compare the exact target commitment."""

    if not isinstance(challenge_input_root, Path) or not challenge_input_root.is_dir():
        raise PwnDependencyStateError(
            "dependency_source_root_invalid"
        )
    selected = _latest_graph_wrapper(state, graph_id=graph_id)
    if selected is None:
        raise PwnDependencyStateError("dependency_graph_not_found")
    validate_pwn_dependency_state_graph(state)
    graph = selected[1]["graph"]
    assert isinstance(graph, dict)
    static_target = graph["static_target"]
    assert isinstance(static_target, dict)
    manifest = inventory_challenge(challenge_input_root)
    locator = static_target["source_locator"]
    source = next(
        (
            item
            for item in manifest.files
            if item.path == locator
        ),
        None,
    )
    if (
        manifest.manifest_sha256
        != static_target["source_manifest_sha256"]
        or source is None
        or source.sha256 != static_target["source_sha256"]
        or source.size != static_target["source_size_bytes"]
    ):
        raise PwnDependencyStateError(
            "dependency_static_target_bytes_changed"
        )
    return {
        "manifest_sha256": manifest.manifest_sha256,
        "raw_output_returned": False,
        "source_locator": locator,
        "source_sha256": source.sha256,
        "source_size_bytes": source.size,
    }


__all__ = [
    "PWN_DEPENDENCY_CONTEXT_PROTOCOL",
    "PWN_DEPENDENCY_STATE_JOURNAL_KEY",
    "PWN_DEPENDENCY_STATE_MAX_ARTIFACT_BYTES",
    "PWN_DEPENDENCY_STATE_PROTOCOL",
    "PWN_DEPENDENCY_STATE_SCHEMA_VERSION",
    "PwnDependencyStateError",
    "append_pwn_dependency_state_graph",
    "build_pwn_dependency_state_graph",
    "project_pwn_dependency_context",
    "project_pwn_dependency_failure_capsule",
    "pwn_dependency_artifact_commitments",
    "pwn_dependency_state_graph_errors",
    "verify_pwn_dependency_artifact_bytes",
    "verify_pwn_dependency_static_target",
    "validate_pwn_dependency_state_graph",
]
