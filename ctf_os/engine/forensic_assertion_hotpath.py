"""Temporal, operator-explicit Forensic assertion execution hot path.

One call operates on one already-open Forensic challenge.  It snapshots a
strict value-free operator specification, resolves the exact current confirmed
evidence index and engine-confirmed tool readiness, precommits every request
document and identity before tool one, executes each request in a fresh
challenge-scoped deny-all sandbox, and reduces only through the deterministic
execution and state contracts.

Raw tool bytes are copied only to private challenge artifacts.  They are never
placed in ``state.json``.  This path cannot create a flag candidate, proof,
submission, impact claim, or challenge-status transition.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ctf_os.director.resources import ResourceVector
from ctf_os.engine.forensic_assertion_execution import (
    FORENSIC_ASSERTION_OBSERVATION_DOCUMENT_MAX_BYTES,
    FORENSIC_ASSERTION_OPERATOR_SPEC_MAX_BYTES,
    ForensicAssertionExecutionEvaluation,
    ForensicAssertionExecutionPlan,
    ForensicAssertionExecutionPreflightError,
    ForensicCapturedArtifact,
    ForensicObservationIssue,
    ForensicToolObservationTransport,
    ForensicToolReadiness,
    evaluate_forensic_assertion_execution,
    forensic_tool_readiness_registry_sha256,
    parse_forensic_assertion_operator_spec,
    plan_forensic_assertion_execution,
)
from ctf_os.engine.forensic_assertion_graph import (
    FORENSIC_ASSERTION_MAX_ARTIFACT_BYTES,
)
from ctf_os.engine.forensic_assertion_state import (
    ForensicAssertionStateIds,
    build_forensic_assertion_state_projection,
    validate_forensic_assertion_state_graph,
    validate_forensic_assertion_state_projection,
)
from ctf_os.engine.forensic_index import (
    FORENSIC_INDEX_MAX_BYTES,
    FORENSIC_INDEX_MAX_FILES,
    FORENSIC_INDEX_MAX_PREFIX_BYTES,
    ForensicIndexEvaluation,
    ForensicIndexVerdict,
    ForensicSourceExpectation,
)
from ctf_os.engine.forensic_index_execution import (
    ForensicIndexExecutionEnvelope,
    ForensicIndexExecutionEvaluation,
    ForensicIndexExecutionVerdict,
)
from ctf_os.models import (
    ArtifactReference,
    ChallengeIdentity,
    ChallengeState,
    RunOrigin,
    RunReference,
    RunStatus,
    utc_now,
    validate_forensic_index_execution_state_graph,
)
from ctf_os.sandbox import CommandSpec, NetworkPolicy
from ctf_os.sandbox.files import (
    SafeFileError,
    copy_bounded_regular,
    ensure_private_directory,
    read_bounded_regular,
    read_regular_prefix,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.stages.ingest import inventory_challenge
from ctf_os.store.atomic import (
    StrictJSONError,
    atomic_write_bytes,
    atomic_write_json,
    strict_json_loads,
)

if TYPE_CHECKING:
    from ctf_os.engine.challenge import ChallengeEngine


FORENSIC_ASSERTION_HOTPATH_PROTOCOL = (
    "ctfos.forensic.assertion.hotpath.v1"
)
FORENSIC_ASSERTION_HOTPATH_SCHEMA_VERSION = 1
FORENSIC_ASSERTION_READINESS_PROTOCOL = (
    "ctfos.forensic.assertion.readiness.v1"
)
FORENSIC_ASSERTION_HOTPATH_MAX_ATTEMPTS = 64
FORENSIC_ASSERTION_HOTPATH_MAX_METADATA_BYTES = 8 * 1024 * 1024
FORENSIC_ASSERTION_HOTPATH_MAX_TIMEOUT_SECONDS = 24 * 60 * 60
FORENSIC_ASSERTION_HOTPATH_STREAM_MAX_BYTES = 16 * 1024 * 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,255}$")


class ForensicAssertionHotPathError(RuntimeError):
    """One fail-closed hot-path boundary rejected execution."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class _Snapshot:
    artifact_id: str
    path: str
    sha256: str
    size_bytes: int
    source_locator: str

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "source_locator": self.source_locator,
        }


@dataclass(frozen=True, slots=True)
class _RequestPaths:
    request_path: str
    result_path: str
    validation_path: str

    def to_dict(self) -> dict[str, str]:
        return {
            "request_path": self.request_path,
            "result_path": self.result_path,
            "validation_path": self.validation_path,
        }


def _canonical_json_bytes(value: object) -> bytes:
    try:
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
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_canonical_json_invalid"
        ) from error
    if len(payload) > FORENSIC_ASSERTION_HOTPATH_MAX_METADATA_BYTES:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_metadata_too_large"
        )
    return payload


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(16)}"


def _all_state_ids(state: ChallengeState) -> set[str]:
    values: set[str] = set()
    for collection in (
        state.goals,
        state.facts,
        state.hypotheses,
        state.experiments,
        state.progress_markers,
        state.candidates,
        state.submissions,
        state.artifacts,
        state.runs,
        state.receipts,
        state.sessions,
        state.cycles,
        state.waves,
        state.checkpoints,
        state.targets,
        state.workspace_publishes,
    ):
        values.update(
            item.id
            for item in collection
            if type(getattr(item, "id", None)) is str
        )
    return values


def _safe_projection_ids(
    state: ChallengeState,
    *,
    excluding: set[str] | None = None,
) -> set[str]:
    omitted = excluding or set()
    return {
        value
        for value in _all_state_ids(state)
        if value not in omitted and _SAFE_ID.fullmatch(value) is not None
    }


def _artifact_path(
    artifact_id: str,
    role: str,
) -> str:
    return (
        "artifacts/forensic-assertion-state/"
        f"{role}/{artifact_id}.json"
    )


def _request_paths(run_id: str) -> _RequestPaths:
    root = f"runs/{run_id}/forensic-assertion"
    return _RequestPaths(
        request_path=f"{root}/request.json",
        result_path=f"{root}/result.json",
        validation_path=f"{root}/validation.json",
    )


def _absolute_under(root: Path, relative: str) -> Path:
    if (
        type(relative) is not str
        or not relative
        or relative.startswith("/")
        or "\\" in relative
        or any(
            part in {"", ".", ".."} for part in relative.split("/")
        )
    ):
        raise ForensicAssertionHotPathError(
            "forensic_assertion_path_invalid"
        )
    destination = root.joinpath(*relative.split("/"))
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    return destination


def _read_exact(
    root: Path,
    relative: str,
    *,
    sha256: str,
    size_bytes: int,
    maximum_bytes: int,
) -> bytes:
    try:
        return read_bounded_regular(
            root,
            relative,
            maximum_bytes=maximum_bytes,
            expected_sha256=sha256,
            expected_size=size_bytes,
        )
    except (OSError, SafeFileError, TypeError, ValueError) as error:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_artifact_rebound"
        ) from error


def _snapshot_operator_spec(
    engine: ChallengeEngine,
    state: ChallengeState,
    *,
    client: object,
    locator: str,
    artifact_id: str,
) -> _Snapshot:
    paths = engine.store.challenge_paths(state.identity)
    destination = (
        paths.root
        / _artifact_path(artifact_id, "operator_spec")
    )
    try:
        immutable = engine._snapshot_workspace_file(
            state,
            client,
            locator,
            destination,
        )
    except Exception as error:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_operator_spec_snapshot_failed"
        ) from error
    if immutable.size_bytes > FORENSIC_ASSERTION_OPERATOR_SPEC_MAX_BYTES:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_operator_spec_too_large"
        )
    return _Snapshot(
        artifact_id=artifact_id,
        path=immutable.path.relative_to(paths.root).as_posix(),
        sha256=immutable.sha256,
        size_bytes=immutable.size_bytes,
        source_locator=immutable.source_locator,
    )


def _snapshot_reference(snapshot: _Snapshot) -> ArtifactReference:
    return ArtifactReference(
        id=snapshot.artifact_id,
        path=snapshot.path,
        sha256=snapshot.sha256,
        size=snapshot.size_bytes,
        media_type="application/json",
        extra={
            "context_visibility": "engine_private",
            "forensic_assertion_hotpath": {
                "protocol": FORENSIC_ASSERTION_HOTPATH_PROTOCOL,
                "role": "operator_spec_snapshot",
                "source_locator": snapshot.source_locator,
            },
            "kind": "forensic_assertion_operator_spec_snapshot",
            "protocol": FORENSIC_ASSERTION_HOTPATH_PROTOCOL,
        },
    )


def _typed_index_execution(
    value: object,
) -> ForensicIndexExecutionEvaluation:
    if type(value) is not dict:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_index_evaluation_invalid"
        )
    semantic_raw = value.get("semantic_evaluation")
    envelope_raw = value.get("envelope")
    if type(semantic_raw) is not dict or type(envelope_raw) is not dict:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_index_evaluation_invalid"
        )
    try:
        semantic = ForensicIndexEvaluation(
            verdict=ForensicIndexVerdict(semantic_raw["verdict"]),
            reason_code=semantic_raw["reason_code"],
            source_inventory_sha256=semantic_raw[
                "source_inventory_sha256"
            ],
            tree_sha256=semantic_raw["tree_sha256"],
            index_sha256=semantic_raw["index_sha256"],
            indexed_files=semantic_raw["indexed_files"],
            indexed_bytes=semantic_raw["indexed_bytes"],
            pointer_coverage_ppm=semantic_raw[
                "pointer_coverage_ppm"
            ],
            modality_counts=tuple(
                sorted(semantic_raw["modality_counts"].items())
            ),
        )
        image = envelope_raw["image"]
        receipt = envelope_raw["receipt"]
        request = envelope_raw["request"]
        run = envelope_raw["run"]
        source = envelope_raw["source"]
        stdout = envelope_raw["stdout_artifact"]
        envelope = ForensicIndexExecutionEnvelope(
            category=envelope_raw["category"],
            contest_id=envelope_raw["contest_id"],
            challenge_id=envelope_raw["challenge_id"],
            configuration_epoch=envelope_raw[
                "configuration_epoch"
            ],
            experiment_id=envelope_raw["experiment_id"],
            run_id=run["id"],
            run_origin=run["origin"],
            request_path=request["path"],
            request_sha256=request["sha256"],
            request_size_bytes=request["size_bytes"],
            result_path=run["result_path"],
            validation_path=run["validation_path"],
            receipt_id=receipt["id"],
            image_name=image["name"],
            image_digest=image["digest"],
            source_manifest_sha256=source["manifest_sha256"],
            source_inventory_sha256=source["inventory_sha256"],
            source_file_count=source["file_count"],
            source_total_bytes=source["total_bytes"],
            prefix_coverage_ppm=envelope_raw[
                "prefix_coverage_ppm"
            ],
            stdout_artifact_id=stdout["id"],
            stdout_artifact_path=stdout["path"],
            stdout_artifact_sha256=stdout["sha256"],
            stdout_artifact_size_bytes=stdout["size_bytes"],
        )
        evaluation = ForensicIndexExecutionEvaluation(
            verdict=ForensicIndexExecutionVerdict(value["verdict"]),
            reason_code=value["reason_code"],
            envelope=envelope,
            semantic_evaluation=semantic,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_index_evaluation_invalid"
        ) from error
    if evaluation.to_dict() != value or not evaluation.confirmed:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_index_evaluation_invalid"
        )
    return evaluation


def _current_index_execution(
    state: ChallengeState,
    *,
    evaluation_sha256: str,
    root: Path,
) -> ForensicIndexExecutionEvaluation:
    if _SHA256.fullmatch(evaluation_sha256) is None:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_index_hash_invalid"
        )
    try:
        validate_forensic_index_execution_state_graph(state)
    except ValueError as error:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_current_index_graph_invalid"
        ) from error
    matches: list[ForensicIndexExecutionEvaluation] = []
    for experiment in state.experiments:
        result = experiment.result
        raw = (
            result.get("forensic_index_execution")
            if type(result) is dict
            else None
        )
        if type(raw) is not dict or raw.get("confirmed") is not True:
            continue
        try:
            evaluation = _typed_index_execution(raw)
        except ForensicAssertionHotPathError:
            continue
        envelope = evaluation.envelope
        if (
            evaluation.sha256 == evaluation_sha256
            and envelope is not None
            and envelope.configuration_epoch
            == state.configuration_epoch
            and envelope.source_manifest_sha256
            == state.metadata.get("source_manifest_sha256")
        ):
            matches.append(evaluation)
    if len(matches) != 1:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_current_index_not_unique"
        )
    evaluation = matches[0]
    assert evaluation.envelope is not None
    artifact = next(
        (
            item
            for item in state.artifacts
            if item.id == evaluation.envelope.stdout_artifact_id
        ),
        None,
    )
    if (
        artifact is None
        or artifact.path != evaluation.envelope.stdout_artifact_path
        or artifact.sha256
        != evaluation.envelope.stdout_artifact_sha256
        or artifact.size
        != evaluation.envelope.stdout_artifact_size_bytes
    ):
        raise ForensicAssertionHotPathError(
            "forensic_assertion_index_artifact_rebound"
        )
    _read_exact(
        root,
        artifact.path,
        sha256=artifact.sha256,
        size_bytes=int(artifact.size),
        maximum_bytes=FORENSIC_INDEX_MAX_BYTES,
    )
    return evaluation


def _current_sources(
    engine: ChallengeEngine,
    state: ChallengeState,
) -> tuple[ForensicSourceExpectation, ...]:
    try:
        inventory = inventory_challenge(
            engine.challenge_input(state.identity),
            max_files=FORENSIC_INDEX_MAX_FILES,
            max_total_bytes=128 * 1024**3,
        )
        state_sources = {
            item.path: item for item in state.source_inventory
        }
        if (
            inventory.manifest_sha256
            != state.metadata.get("source_manifest_sha256")
            or len(state_sources) != len(state.source_inventory)
            or len(inventory.files) != len(state.source_inventory)
        ):
            raise ValueError("source inventory changed")
        result: list[ForensicSourceExpectation] = []
        for source in inventory.files:
            bound = state_sources.get(source.path)
            if (
                bound is None
                or bound.kind != "file"
                or bound.sha256 != source.sha256
                or bound.size != source.size
            ):
                raise ValueError("source inventory changed")
            prefix = read_regular_prefix(
                engine.challenge_input(state.identity),
                source.path,
                maximum_prefix_bytes=FORENSIC_INDEX_MAX_PREFIX_BYTES,
                expected_size=source.size,
            )
            result.append(
                ForensicSourceExpectation(
                    path=source.path,
                    sha256=source.sha256,
                    size_bytes=source.size,
                    prefix_sha256=_sha256(prefix),
                    prefix_size_bytes=len(prefix),
                )
            )
    except (
        OSError,
        SafeFileError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as error:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_current_sources_invalid"
        ) from error
    return tuple(sorted(result, key=lambda item: item.path.encode()))


def _operator_document(payload: bytes) -> dict[str, object]:
    try:
        value = strict_json_loads(
            payload,
            max_bytes=FORENSIC_ASSERTION_OPERATOR_SPEC_MAX_BYTES,
            max_depth=24,
        )
    except (
        StrictJSONError,
        RecursionError,
        UnicodeError,
        ValueError,
    ) as error:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_operator_spec_json_invalid"
        ) from error
    if (
        type(value) is not dict
        or payload != _canonical_json_bytes(value)
    ):
        raise ForensicAssertionHotPathError(
            "forensic_assertion_operator_spec_not_canonical"
        )
    return value


def _readiness_from_operator(
    engine: ChallengeEngine,
    state: ChallengeState,
    operator: dict[str, object],
) -> tuple[ForensicToolReadiness, ...]:
    tools_raw = operator.get("tools")
    if type(tools_raw) is not list or not tools_raw:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_readiness_registry_invalid"
        )
    values: list[ForensicToolReadiness] = []
    for raw in tools_raw:
        if type(raw) is not dict:
            raise ForensicAssertionHotPathError(
                "forensic_assertion_readiness_registry_invalid"
            )
        artifact_raw = raw.get("readiness_artifact")
        if type(artifact_raw) is not dict:
            raise ForensicAssertionHotPathError(
                "forensic_assertion_readiness_registry_invalid"
            )
        try:
            readiness = ForensicToolReadiness(
                tool_id=raw["tool_id"],
                independence_family=raw["independence_family"],
                tool_version_sha256=raw["tool_version_sha256"],
                runtime_image_digest=raw["runtime_image_digest"],
                supported_pointer_kinds=tuple(
                    raw["supported_pointer_kinds"]
                ),
                command_template=tuple(raw["command_template"]),
                readiness_generation=raw["readiness_generation"],
                readiness_artifact_id=artifact_raw["artifact_id"],
                readiness_artifact_sha256=artifact_raw["sha256"],
                readiness_artifact_size_bytes=artifact_raw[
                    "size_bytes"
                ],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ForensicAssertionHotPathError(
                "forensic_assertion_readiness_registry_invalid"
            ) from error
        if readiness.to_dict() != raw:
            raise ForensicAssertionHotPathError(
                "forensic_assertion_readiness_registry_invalid"
            )
        values.append(readiness)
    try:
        registry_sha256 = forensic_tool_readiness_registry_sha256(
            tuple(values)
        )
    except (TypeError, ValueError) as error:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_readiness_registry_invalid"
        ) from error
    if operator.get("readiness_registry_sha256") != registry_sha256:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_readiness_registry_rebound"
        )
    paths = engine.store.challenge_paths(state.identity)
    expected_image = engine.config.runtime.image_digest
    if (
        type(expected_image) is not str
        or _IMAGE_DIGEST.fullmatch(expected_image) is None
    ):
        raise ForensicAssertionHotPathError(
            "forensic_assertion_runtime_image_unpinned"
        )
    for readiness in values:
        artifact = next(
            (
                item
                for item in state.artifacts
                if item.id == readiness.readiness_artifact_id
            ),
            None,
        )
        expected_marker = {
            "configuration_epoch": state.configuration_epoch,
            "confirmed": True,
            "protocol": FORENSIC_ASSERTION_READINESS_PROTOCOL,
            "readiness_registry_sha256": registry_sha256,
            "schema_version": 1,
            "tool": readiness.to_dict(),
        }
        if (
            artifact is None
            or artifact.sha256
            != readiness.readiness_artifact_sha256
            or artifact.size
            != readiness.readiness_artifact_size_bytes
            or type(artifact.extra) is not dict
            or artifact.extra.get("forensic_assertion_readiness")
            != expected_marker
            or readiness.runtime_image_digest != expected_image
        ):
            raise ForensicAssertionHotPathError(
                "forensic_assertion_readiness_artifact_rebound"
            )
        _read_exact(
            paths.root,
            artifact.path,
            sha256=artifact.sha256,
            size_bytes=int(artifact.size),
            maximum_bytes=1024 * 1024,
        )
    return tuple(values)


def _index_hash_from_operator(
    operator: dict[str, object],
) -> str:
    index_root = operator.get("index_root")
    value = (
        index_root.get("index_execution_evaluation_sha256")
        if type(index_root) is dict
        else None
    )
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_operator_index_root_invalid"
        )
    return value


def _preissue_artifact_reference(
    *,
    artifact_id: str,
    path: str,
    sha256: str,
    size_bytes: int,
    role: str,
) -> ArtifactReference:
    return ArtifactReference(
        id=artifact_id,
        path=path,
        sha256=sha256,
        size=size_bytes,
        media_type="application/json",
        extra={
            "context_visibility": "engine_private",
            "forensic_assertion_hotpath": {
                "protocol": FORENSIC_ASSERTION_HOTPATH_PROTOCOL,
                "role": role,
            },
            "kind": f"forensic_assertion_{role}",
            "protocol": FORENSIC_ASSERTION_HOTPATH_PROTOCOL,
        },
    )


def _preissue_attempts(
    state: ChallengeState,
) -> dict[str, object]:
    value = state.extra.get("forensic_assertion_preissues")
    if value is None:
        return {}
    if type(value) is not dict:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_preissue_state_invalid"
        )
    if len(value) >= FORENSIC_ASSERTION_HOTPATH_MAX_ATTEMPTS:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_preissue_history_full"
        )
    return value


def _attempt_document(
    *,
    attempt_id: str,
    state: ChallengeState,
    spec_snapshot: _Snapshot,
    execution_plan: ForensicAssertionExecutionPlan,
    state_ids: ForensicAssertionStateIds,
    request_payloads: tuple[bytes, ...],
) -> dict[str, object]:
    requests: list[dict[str, object]] = []
    for request, payload in zip(
        execution_plan.requests,
        request_payloads,
        strict=True,
    ):
        paths = _request_paths(request.run_id)
        requests.append(
            {
                "artifact": {
                    "artifact_id": request.artifact_id,
                    "path": request.artifact_path,
                },
                "capture": None,
                "observation": {
                    "observation_id": request.observation_id,
                    "path": request.observation_path,
                },
                "ordinal": len(requests) + 1,
                "receipt_id": request.receipt_id,
                "request": {
                    "path": paths.request_path,
                    "request_id": request.request_id,
                    "sha256": _sha256(payload),
                    "size_bytes": len(payload),
                },
                "run_id": request.run_id,
                "status": "preissued",
                "terminal": None,
                "tool": {
                    "independence_family": (
                        request.independence_family
                    ),
                    "runtime_image_digest": (
                        request.runtime_image_digest
                    ),
                    "tool_id": request.tool_id,
                },
            }
        )
    value = {
        "active_run_id": None,
        "attempt_id": attempt_id,
        "authorities": {
            "automatic_submission_authorized": False,
            "candidate_authorized": False,
            "challenge_proof_satisfied": False,
            "executed_fact_authorized": False,
            "flag_proven": False,
            "impact_proven": False,
            "progress_authorized": False,
            "proof_authorized": False,
            "status_transition_authorized": False,
        },
        "base_revision": state.revision,
        "configuration_epoch": state.configuration_epoch,
        "execution_plan": execution_plan.to_dict(),
        "execution_plan_sha256": (
            execution_plan.execution_plan_sha256
        ),
        "expected_state_ids": {
            "evaluation_artifact_id": (
                state_ids.evaluation_artifact_id
            ),
            "experiment_id": state_ids.experiment_id,
            "fact_id": state_ids.fact_id,
            "operator_spec_artifact_id": (
                state_ids.operator_spec_artifact_id
            ),
            "plan_artifact_id": state_ids.plan_artifact_id,
            "progress_id": state_ids.progress_id,
        },
        "index_execution_evaluation_sha256": (
            execution_plan.specification.plan.inventory_root
            .index_execution_evaluation_sha256
        ),
        "operator_spec": spec_snapshot.to_dict(),
        "protocol": FORENSIC_ASSERTION_HOTPATH_PROTOCOL,
        "readiness_registry_sha256": (
            execution_plan.specification.readiness_registry_sha256
        ),
        "requests": requests,
        "schema_version": FORENSIC_ASSERTION_HOTPATH_SCHEMA_VERSION,
        "source_inventory_sha256": (
            execution_plan.specification.plan.inventory_root
            .source_inventory_sha256
        ),
        "source_manifest_sha256": (
            execution_plan.specification.plan.inventory_root
            .source_manifest_sha256
        ),
        "status": "preissued",
        "terminal": None,
    }
    _canonical_json_bytes(value)
    return value


def _verify_external_bindings(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    configuration_epoch: int,
    spec_snapshot: _Snapshot,
    spec_payload: bytes,
    operator: dict[str, object],
    index_execution: ForensicIndexExecutionEvaluation,
    sources: tuple[ForensicSourceExpectation, ...],
    readiness: tuple[ForensicToolReadiness, ...],
    execution_plan: ForensicAssertionExecutionPlan,
    request_payloads: tuple[bytes, ...],
) -> None:
    current = engine.store.load(identity, recover=False)
    paths = engine.store.challenge_paths(identity)
    if (
        current.category != "forensics"
        or current.schema_version < STATE_SCHEMA_VERSION
        or current.configuration_epoch != configuration_epoch
    ):
        raise ForensicAssertionHotPathError(
            "forensic_assertion_current_configuration_changed"
        )
    observed_spec = _read_exact(
        paths.root,
        spec_snapshot.path,
        sha256=spec_snapshot.sha256,
        size_bytes=spec_snapshot.size_bytes,
        maximum_bytes=FORENSIC_ASSERTION_OPERATOR_SPEC_MAX_BYTES,
    )
    if observed_spec != spec_payload:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_operator_spec_snapshot_rebound"
        )
    current_sources = _current_sources(engine, current)
    current_readiness = _readiness_from_operator(
        engine,
        current,
        operator,
    )
    current_index = _current_index_execution(
        current,
        evaluation_sha256=index_execution.sha256,
        root=paths.root,
    )
    try:
        reparsed = parse_forensic_assertion_operator_spec(
            spec_payload,
            current_index_execution=current_index,
            current_sources=current_sources,
            current_readiness=current_readiness,
        )
    except (
        ForensicAssertionExecutionPreflightError,
        TypeError,
        ValueError,
    ) as error:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_current_spec_revalidation_failed"
        ) from error
    if (
        current_sources != sources
        or current_readiness != readiness
        or current_index != index_execution
        or reparsed != execution_plan.specification
    ):
        raise ForensicAssertionHotPathError(
            "forensic_assertion_current_binding_rebound"
        )
    for request, expected_payload in zip(
        execution_plan.requests,
        request_payloads,
        strict=True,
    ):
        paths_for_run = _request_paths(request.run_id)
        payload = _read_exact(
            paths.root,
            paths_for_run.request_path,
            sha256=request.request_sha256,
            size_bytes=len(expected_payload),
            maximum_bytes=256 * 1024,
        )
        if (
            paths_for_run.request_path != request.request_path
            or expected_payload != request.canonical_bytes
            or payload != expected_payload
        ):
            raise ForensicAssertionHotPathError(
                "forensic_assertion_preissued_request_rebound"
            )


def _terminalize(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    attempt_id: str,
    error: BaseException,
) -> None:
    # An external-binding failure can be caused by one of the preissued
    # artifacts itself being replaced.  Canonical state must not retain a
    # digest claim for bytes that no longer match it, but the private file and
    # the original commitment in the attempt document remain available for
    # diagnosis.
    from ctf_os.store import ArtifactValidationError, validate_artifact

    challenge_root = engine.store.challenge_paths(identity).root

    def apply(state: ChallengeState) -> None:
        attempts = state.extra.get("forensic_assertion_preissues")
        if type(attempts) is not dict:
            return
        attempt = attempts.get(attempt_id)
        if type(attempt) is not dict:
            return
        if attempt.get("status") in {"completed", "interrupted"}:
            return
        request_values = attempt.get("requests")
        run_ids: set[str] = set()
        preissue_artifact_ids: set[str] = set()
        operator_spec = attempt.get("operator_spec")
        if type(operator_spec) is dict:
            artifact_id = operator_spec.get("artifact_id")
            if type(artifact_id) is str:
                preissue_artifact_ids.add(artifact_id)
        expected_state_ids = attempt.get("expected_state_ids")
        if type(expected_state_ids) is dict:
            plan_artifact_id = expected_state_ids.get(
                "plan_artifact_id"
            )
            if type(plan_artifact_id) is str:
                preissue_artifact_ids.add(plan_artifact_id)
        if type(request_values) is list:
            for request in request_values:
                if type(request) is not dict:
                    continue
                run_id = request.get("run_id")
                if type(run_id) is str:
                    run_ids.add(run_id)
                request_binding = request.get("request")
                if type(request_binding) is dict:
                    request_id = request_binding.get("request_id")
                    if type(request_id) is str:
                        preissue_artifact_ids.add(request_id)
                if request.get("status") in {
                    "preissued",
                    "running",
                }:
                    request["status"] = "interrupted"
                    request["terminal"] = {
                        "at": utc_now(),
                        "reason_code": (
                            "forensic_assertion_execution_interrupted"
                        ),
                    }
        for run in state.runs:
            if (
                run.id in run_ids
                and run.status in {RunStatus.CREATED, RunStatus.RUNNING}
            ):
                run.status = RunStatus.INTERRUPTED
        invalidated_artifact_ids: list[str] = []
        retained_artifacts: list[ArtifactReference] = []
        for artifact in state.artifacts:
            if artifact.id not in preissue_artifact_ids:
                retained_artifacts.append(artifact)
                continue
            try:
                validate_artifact(challenge_root, artifact)
            except ArtifactValidationError:
                invalidated_artifact_ids.append(artifact.id)
            else:
                retained_artifacts.append(artifact)
        state.artifacts = retained_artifacts
        attempt["active_run_id"] = None
        attempt["status"] = "interrupted"
        attempt["terminal"] = {
            "at": utc_now(),
            "error_type": type(error).__name__[:128],
            "invalidated_artifact_ids": sorted(
                invalidated_artifact_ids
            ),
            "reason_code": (
                "forensic_assertion_execution_interrupted"
            ),
        }

    try:
        engine.store.update(identity, apply)
    except BaseException as terminal_error:
        error.add_note(
            "Forensic assertion interruption terminalization failed: "
            f"{type(terminal_error).__name__}"
        )


def _projection_owned_ids(
    execution_plan: ForensicAssertionExecutionPlan,
    state_ids: ForensicAssertionStateIds,
) -> set[str]:
    values = {
        state_ids.experiment_id,
        state_ids.operator_spec_artifact_id,
        state_ids.plan_artifact_id,
        state_ids.evaluation_artifact_id,
        *(
            value
            for request in execution_plan.requests
            for value in (
                request.request_id,
                request.run_id,
                request.observation_id,
                request.receipt_id,
                request.artifact_id,
            )
        ),
    }
    if state_ids.fact_id is not None:
        values.add(state_ids.fact_id)
    if state_ids.progress_id is not None:
        values.add(state_ids.progress_id)
    return values


def _copy_workspace_capture(
    *,
    client: object,
    workspace: Path,
    locator: str,
    destination: Path,
    maximum_bytes: int,
) -> bytes:
    try:
        reference = client.register_artifact(
            locator,
            maximum_bytes=maximum_bytes,
        )
        if reference.scope_fingerprint != client.scope_fingerprint:
            raise ForensicAssertionHotPathError(
                "forensic_assertion_capture_scope_rebound"
            )
        immutable = copy_bounded_regular(
            workspace,
            reference.locator,
            destination,
            maximum_bytes=maximum_bytes,
            expected_sha256=reference.sha256,
            expected_size=reference.size_bytes,
            mode=0o400,
        )
        return immutable.path.read_bytes()
    except ForensicAssertionHotPathError:
        raise
    except (OSError, SafeFileError, TypeError, ValueError) as error:
        raise ForensicAssertionHotPathError(
            "forensic_assertion_capture_failed"
        ) from error


def execute_forensic_assertion_hotpath(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    operator_spec_locator: str,
    hypothesis_ids: tuple[str, ...] = (),
    timeout_seconds: int = 900,
    _session_owned: bool = False,
) -> tuple[ChallengeState, ForensicAssertionExecutionEvaluation]:
    """Run one explicit assertion wave without candidate/proof authority."""

    # Lazy imports avoid a module cycle when ChallengeEngine later exposes this
    # function as a convenience method.
    from ctf_os.engine.challenge import (
        EngineError,
        SessionAlreadyRunning,
    )
    from ctf_os.store import ChallengeLock, LockTimeout

    if not _session_owned:
        lock = ChallengeLock(
            engine.store.challenge_paths(identity).runtime
            / "session.lock",
            timeout=0,
        )
        try:
            lock.acquire()
        except LockTimeout as error:
            raise SessionAlreadyRunning(
                f"another session already owns {identity.key}"
            ) from error
        try:
            engine._recover_session_boundary(identity)
            return execute_forensic_assertion_hotpath(
                engine,
                identity,
                operator_spec_locator=operator_spec_locator,
                hypothesis_ids=hypothesis_ids,
                timeout_seconds=timeout_seconds,
                _session_owned=True,
            )
        finally:
            lock.release()

    state = engine.store.load(identity)
    if (
        state.category != "forensics"
        or state.schema_version < STATE_SCHEMA_VERSION
    ):
        raise EngineError(
            "Forensic assertion execution requires one schema-v2 "
            "Forensic challenge"
        )
    if (
        type(timeout_seconds) is not int
        or not 1
        <= timeout_seconds
        <= FORENSIC_ASSERTION_HOTPATH_MAX_TIMEOUT_SECONDS
    ):
        raise EngineError(
            "Forensic assertion timeout must be 1..86400 seconds"
        )
    if (
        type(hypothesis_ids) is not tuple
        or any(type(item) is not str for item in hypothesis_ids)
        or len(set(hypothesis_ids)) != len(hypothesis_ids)
        or any(
            item not in {hypothesis.id for hypothesis in state.hypotheses}
            for item in hypothesis_ids
        )
    ):
        raise EngineError(
            "Forensic assertion hypothesis references are invalid"
        )
    if (
        type(engine.config.runtime.image_digest) is not str
        or _IMAGE_DIGEST.fullmatch(
            engine.config.runtime.image_digest
        )
        is None
    ):
        raise EngineError(
            "Forensic assertion execution requires a digest-pinned image"
        )

    paths = engine.store.challenge_paths(identity)
    attempt_id = _new_id("forensic-assertion")
    attempt_root = ensure_private_directory(
        paths.artifacts
        / "forensic-assertion-hotpath"
        / attempt_id
    )
    initial_client = engine.sandbox(
        state,
        network_policy_override=NetworkPolicy.deny_all(),
    )
    operator_artifact_id = _new_id("A-forensic-operator")
    spec_snapshot = _snapshot_operator_spec(
        engine,
        state,
        client=initial_client,
        locator=operator_spec_locator,
        artifact_id=operator_artifact_id,
    )
    spec_payload = _read_exact(
        paths.root,
        spec_snapshot.path,
        sha256=spec_snapshot.sha256,
        size_bytes=spec_snapshot.size_bytes,
        maximum_bytes=FORENSIC_ASSERTION_OPERATOR_SPEC_MAX_BYTES,
    )
    operator = _operator_document(spec_payload)
    index_sha256 = _index_hash_from_operator(operator)
    sources = _current_sources(engine, state)
    readiness = _readiness_from_operator(engine, state, operator)
    index_execution = _current_index_execution(
        state,
        evaluation_sha256=index_sha256,
        root=paths.root,
    )
    try:
        specification = parse_forensic_assertion_operator_spec(
            spec_payload,
            current_index_execution=index_execution,
            current_sources=sources,
            current_readiness=readiness,
        )
    except (
        ForensicAssertionExecutionPreflightError,
        TypeError,
        ValueError,
    ) as error:
        raise EngineError(
            f"Forensic assertion operator specification rejected: {error}"
        ) from error

    issue_count = 0
    for pointer in specification.plan.pointers:
        families = {
            item.independence_family
            for item in readiness
            if pointer.kind in item.supported_pointer_kinds
        }
        issue_count += min(2, len(families))
    issues = tuple(
        ForensicObservationIssue(
            request_id=_new_id("FREQ"),
            run_id=_new_id("FRUN"),
            observation_id=_new_id("FOBS"),
            receipt_id=_new_id("FREC"),
            artifact_id=_new_id("FART"),
            execution_nonce=secrets.token_bytes(32),
        )
        for _ in range(issue_count)
    )
    try:
        execution_plan = plan_forensic_assertion_execution(
            specification,
            issues,
        )
    except (
        ForensicAssertionExecutionPreflightError,
        TypeError,
        ValueError,
    ) as error:
        raise EngineError(
            f"Forensic assertion execution plan rejected: {error}"
        ) from error

    state_ids = ForensicAssertionStateIds(
        experiment_id=_new_id("E-forensic-assertion"),
        operator_spec_artifact_id=operator_artifact_id,
        plan_artifact_id=_new_id("A-forensic-plan"),
        evaluation_artifact_id=_new_id("A-forensic-evaluation"),
        fact_id=_new_id("F-forensic-assertion"),
        progress_id=_new_id("P-forensic-assertion"),
    )
    issued = _projection_owned_ids(execution_plan, state_ids)
    reserved = _all_state_ids(state)
    if (
        len(issued)
        != 6 + 5 * len(execution_plan.requests)
        or reserved & issued
    ):
        raise EngineError(
            "Forensic assertion preissued identifiers collide globally"
        )

    plan_payload = execution_plan.canonical_bytes
    plan_path = _artifact_path(
        state_ids.plan_artifact_id,
        "execution_plan",
    )
    atomic_write_bytes(
        _absolute_under(paths.root, plan_path),
        plan_payload,
        mode=0o400,
    )
    request_payloads: list[bytes] = []
    run_references: list[RunReference] = []
    request_references: list[ArtifactReference] = []
    for request in execution_plan.requests:
        payload = request.canonical_bytes
        run_paths = _request_paths(request.run_id)
        if run_paths.request_path != request.request_path:
            raise EngineError(
                "Forensic assertion request path derivation failed"
            )
        atomic_write_bytes(
            _absolute_under(paths.root, run_paths.request_path),
            payload,
            mode=0o400,
        )
        request_payloads.append(payload)
        run_references.append(
            RunReference(
                id=request.run_id,
                base_revision=state.revision,
                status=RunStatus.CREATED,
                request_path=run_paths.request_path,
                result_path=run_paths.result_path,
                validation_path=run_paths.validation_path,
                role="forensic-assertion",
                origin=RunOrigin.OPERATOR_TOOL,
                configuration_epoch=state.configuration_epoch,
                created_at=utc_now(),
                extra={
                    "attempt_id": attempt_id,
                    "forensic_assertion_hotpath": {
                        "protocol": (
                            FORENSIC_ASSERTION_HOTPATH_PROTOCOL
                        ),
                        "request_id": request.request_id,
                        "request_sha256": request.request_sha256,
                    },
                    "protocol": (
                        FORENSIC_ASSERTION_HOTPATH_PROTOCOL
                    ),
                },
            )
        )
        request_references.append(
            _preissue_artifact_reference(
                artifact_id=request.request_id,
                path=request.request_path,
                sha256=request.request_sha256,
                size_bytes=len(payload),
                role="preissued_request",
            )
        )
    selected_request_payloads = tuple(request_payloads)
    preissue_artifacts = (
        _snapshot_reference(spec_snapshot),
        _preissue_artifact_reference(
            artifact_id=state_ids.plan_artifact_id,
            path=plan_path,
            sha256=_sha256(plan_payload),
            size_bytes=len(plan_payload),
            role="execution_plan",
        ),
        *request_references,
    )
    attempt = _attempt_document(
        attempt_id=attempt_id,
        state=state,
        spec_snapshot=spec_snapshot,
        execution_plan=execution_plan,
        state_ids=state_ids,
        request_payloads=selected_request_payloads,
    )
    attempt_sha256 = _sha256(_canonical_json_bytes(attempt))

    def verify_external() -> None:
        _verify_external_bindings(
            engine,
            identity,
            configuration_epoch=state.configuration_epoch,
            spec_snapshot=spec_snapshot,
            spec_payload=spec_payload,
            operator=operator,
            index_execution=index_execution,
            sources=sources,
            readiness=readiness,
            execution_plan=execution_plan,
            request_payloads=selected_request_payloads,
        )

    def commit_preissue(current: ChallengeState) -> None:
        if (
            current.revision != state.revision
            or current.configuration_epoch != state.configuration_epoch
            or _all_state_ids(current) != reserved
        ):
            raise EngineError(
                "Forensic assertion state changed before preissue"
            )
        attempts = _preissue_attempts(current)
        if any(
            type(value) is dict
            and value.get("status") in {"preissued", "running"}
            for value in attempts.values()
        ):
            raise EngineError(
                "another Forensic assertion execution is active"
            )
        current.runs.extend(copy.deepcopy(run_references))
        current.artifacts.extend(copy.deepcopy(preissue_artifacts))
        attempts[attempt_id] = copy.deepcopy(attempt)
        current.extra["forensic_assertion_preissues"] = attempts

    committed_preissue = engine.store.update(
        identity,
        commit_preissue,
        expected_revision=state.revision,
        pre_replace_guard=verify_external,
    )
    try:
        committed_attempts = committed_preissue.extra.get(
            "forensic_assertion_preissues"
        )
        committed_attempt = (
            committed_attempts.get(attempt_id)
            if type(committed_attempts) is dict
            else None
        )
        if (
            committed_attempt != attempt
            or _sha256(_canonical_json_bytes(committed_attempt))
            != attempt_sha256
        ):
            raise EngineError(
                "Forensic assertion temporal preissue was not committed"
            )

        transports: list[ForensicToolObservationTransport] = []
        observation_wall_seconds: dict[str, float] = {}
        deadline = time.monotonic() + timeout_seconds
        for ordinal, (request, request_payload) in enumerate(
            zip(
                execution_plan.requests,
                selected_request_payloads,
                strict=True,
            ),
            start=1,
        ):
            verify_external()
            latest = engine.store.load(identity, recover=False)

            def mark_running(current: ChallengeState) -> None:
                attempts = current.extra.get(
                    "forensic_assertion_preissues"
                )
                active = (
                    attempts.get(attempt_id)
                    if type(attempts) is dict
                    else None
                )
                request_states = (
                    active.get("requests")
                    if type(active) is dict
                    else None
                )
                run = next(
                    (
                        item
                        for item in current.runs
                        if item.id == request.run_id
                    ),
                    None,
                )
                if (
                    type(active) is not dict
                    or active.get("status")
                    not in {"preissued", "running"}
                    or active.get("terminal") is not None
                    or type(request_states) is not list
                    or len(request_states)
                    != len(execution_plan.requests)
                    or request_states[ordinal - 1].get("status")
                    != "preissued"
                    or run is None
                    or run.status is not RunStatus.CREATED
                ):
                    raise EngineError(
                        "Forensic assertion run is not preissued"
                    )
                run.status = RunStatus.RUNNING
                active["active_run_id"] = request.run_id
                active["status"] = "running"
                request_states[ordinal - 1]["status"] = "running"

            engine.store.update(
                identity,
                mark_running,
                expected_revision=latest.revision,
                pre_replace_guard=verify_external,
            )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ForensicAssertionHotPathError(
                    "forensic_assertion_timeout_exhausted"
                )
            work = ensure_private_directory(
                paths.runtime
                / "forensic-assertion-live"
                / attempt_id
                / request.run_id
                / "work"
            )
            if any(work.iterdir()):
                raise ForensicAssertionHotPathError(
                    "forensic_assertion_workspace_not_fresh"
                )
            client = engine.sandbox(
                engine.store.load(identity, recover=False),
                workspace_override=work,
                challenge_dir_override=engine.challenge_input(identity),
                network_policy_override=NetworkPolicy.deny_all(),
            )
            client.initialize_workspace()
            atomic_write_bytes(
                _absolute_under(work, request.request_path),
                request_payload,
                mode=0o400,
            )
            _absolute_under(work, request.observation_path)
            _absolute_under(work, request.artifact_path)
            started = time.monotonic()
            result = client.run(
                CommandSpec(
                    argv=request.command_argv,
                    timeout_seconds=max(
                        1,
                        min(
                            timeout_seconds,
                            int(math.ceil(remaining)),
                        ),
                    ),
                    summary_bytes=0,
                    network_target=None,
                    resource_request=ResourceVector(
                        cpu=1,
                        memory_mib=2 * 1024,
                    ),
                    deadline_monotonic_seconds=deadline,
                )
            )
            wall_seconds = time.monotonic() - started
            observed_output = _copy_workspace_capture(
                client=client,
                workspace=work,
                locator=request.artifact_path,
                destination=_absolute_under(
                    paths.root,
                    request.artifact_path,
                ),
                maximum_bytes=FORENSIC_ASSERTION_MAX_ARTIFACT_BYTES,
            )
            observed_document = _copy_workspace_capture(
                client=client,
                workspace=work,
                locator=request.observation_path,
                destination=_absolute_under(
                    paths.root,
                    request.observation_path,
                ),
                maximum_bytes=(
                    FORENSIC_ASSERTION_OBSERVATION_DOCUMENT_MAX_BYTES
                ),
            )
            transport_document = observed_document
            transport_succeeded = (
                result.status == "completed"
                and type(result.exit_code) is int
                and result.exit_code == 0
                and result.timed_out is False
                and result.orchestration_error is None
            )
            if not transport_succeeded:
                transport_document = b"{}\n"
            transports.append(
                ForensicToolObservationTransport(
                    request_path=request.request_path,
                    request_payload=request_payload,
                    observation_path=request.observation_path,
                    observation_payload=transport_document,
                    artifact=ForensicCapturedArtifact(
                        artifact_id=request.artifact_id,
                        path=request.artifact_path,
                        payload=observed_output,
                    ),
                )
            )
            observation_wall_seconds[request.run_id] = wall_seconds
            result_paths = _request_paths(request.run_id)
            atomic_write_json(
                _absolute_under(paths.root, result_paths.result_path),
                {
                    "artifact": {
                        "path": request.artifact_path,
                        "sha256": _sha256(observed_output),
                        "size_bytes": len(observed_output),
                    },
                    "observation": {
                        "path": request.observation_path,
                        "sha256": _sha256(observed_document),
                        "size_bytes": len(observed_document),
                    },
                    "protocol": FORENSIC_ASSERTION_HOTPATH_PROTOCOL,
                    "request_id": request.request_id,
                    "run_id": request.run_id,
                    "sandbox": {
                        "duration_ms": result.duration_ms,
                        "exit_code": result.exit_code,
                        "status": result.status,
                        "timed_out": result.timed_out,
                    },
                },
                mode=0o400,
            )
            atomic_write_json(
                _absolute_under(
                    paths.root,
                    result_paths.validation_path,
                ),
                {
                    "network": "none",
                    "ok": transport_succeeded,
                    "protocol": FORENSIC_ASSERTION_HOTPATH_PROTOCOL,
                    "request_sha256": request.request_sha256,
                    "workspace": "fresh",
                },
                mode=0o400,
            )
            verify_external()
            captured_base = engine.store.load(
                identity,
                recover=False,
            )

            def commit_capture(current: ChallengeState) -> None:
                attempts = current.extra.get(
                    "forensic_assertion_preissues"
                )
                active = (
                    attempts.get(attempt_id)
                    if type(attempts) is dict
                    else None
                )
                request_states = (
                    active.get("requests")
                    if type(active) is dict
                    else None
                )
                run = next(
                    (
                        item
                        for item in current.runs
                        if item.id == request.run_id
                    ),
                    None,
                )
                if (
                    type(active) is not dict
                    or active.get("status") != "running"
                    or active.get("active_run_id") != request.run_id
                    or type(request_states) is not list
                    or request_states[ordinal - 1].get("status")
                    != "running"
                    or run is None
                    or run.status is not RunStatus.RUNNING
                ):
                    raise EngineError(
                        "Forensic assertion capture cannot be committed"
                    )
                request_states[ordinal - 1]["capture"] = {
                    "artifact": {
                        "path": request.artifact_path,
                        "sha256": _sha256(observed_output),
                        "size_bytes": len(observed_output),
                    },
                    "observation": {
                        "path": request.observation_path,
                        "sha256": _sha256(observed_document),
                        "size_bytes": len(observed_document),
                    },
                    "sandbox": {
                        "duration_ms": result.duration_ms,
                        "exit_code": result.exit_code,
                        "status": result.status,
                        "timed_out": result.timed_out,
                    },
                }
                request_states[ordinal - 1]["status"] = "captured"
                request_states[ordinal - 1]["terminal"] = {
                    "at": utc_now(),
                    "reason_code": (
                        "forensic_assertion_transport_captured"
                    ),
                }
                run.status = (
                    RunStatus.TIMED_OUT
                    if result.timed_out
                    else RunStatus.COMPLETED
                    if transport_succeeded
                    else RunStatus.FAILED
                )
                active["active_run_id"] = None

            engine.store.update(
                identity,
                commit_capture,
                expected_revision=captured_base.revision,
                pre_replace_guard=verify_external,
            )

        verify_external()
        evaluation = evaluate_forensic_assertion_execution(
            execution_plan,
            tuple(transports),
            operator_spec_payload=spec_payload,
            current_index_execution=index_execution,
            current_sources=sources,
            current_readiness=readiness,
        )
        evaluation_path = _artifact_path(
            state_ids.evaluation_artifact_id,
            "execution_evaluation",
        )
        atomic_write_bytes(
            _absolute_under(paths.root, evaluation_path),
            evaluation.canonical_bytes,
            mode=0o400,
        )
        final_base = engine.store.load(identity, recover=False)
        projection_ids = state_ids
        if not evaluation.confirmed:
            projection_ids = ForensicAssertionStateIds(
                experiment_id=state_ids.experiment_id,
                operator_spec_artifact_id=(
                    state_ids.operator_spec_artifact_id
                ),
                plan_artifact_id=state_ids.plan_artifact_id,
                evaluation_artifact_id=(
                    state_ids.evaluation_artifact_id
                ),
                fact_id=None,
                progress_id=None,
            )
        projection_owned = _projection_owned_ids(
            execution_plan,
            state_ids,
        )
        projection = build_forensic_assertion_state_projection(
            evaluation,
            execution_plan,
            spec_payload,
            identity=identity,
            configuration_epoch=state.configuration_epoch,
            base_revision=state.revision,
            ids=projection_ids,
            hypothesis_ids=hypothesis_ids,
            evaluated_at=utc_now(),
            timeout_seconds=timeout_seconds,
            run_origin=RunOrigin.OPERATOR_TOOL,
            observation_wall_seconds={
                record.run_id: observation_wall_seconds[record.run_id]
                for record in evaluation.records
            },
            existing_global_ids=_safe_projection_ids(
                final_base,
                excluding=projection_owned,
            ),
        )

        def verify_final() -> None:
            verify_external()
            for request, payload in zip(
                execution_plan.requests,
                selected_request_payloads,
                strict=True,
            ):
                _read_exact(
                    paths.root,
                    request.request_path,
                    sha256=request.request_sha256,
                    size_bytes=len(payload),
                    maximum_bytes=256 * 1024,
                )
            for record in evaluation.records:
                _read_exact(
                    paths.root,
                    record.observation_path,
                    sha256=record.observation_document_sha256,
                    size_bytes=record.observation_document_size_bytes,
                    maximum_bytes=(
                        FORENSIC_ASSERTION_OBSERVATION_DOCUMENT_MAX_BYTES
                    ),
                )
                _read_exact(
                    paths.root,
                    record.artifact_path,
                    sha256=record.artifact.sha256,
                    size_bytes=record.artifact.size_bytes,
                    maximum_bytes=(
                        FORENSIC_ASSERTION_MAX_ARTIFACT_BYTES
                    ),
                )
            if _read_exact(
                paths.root,
                plan_path,
                sha256=_sha256(plan_payload),
                size_bytes=len(plan_payload),
                maximum_bytes=8 * 1024 * 1024,
            ) != plan_payload:
                raise ForensicAssertionHotPathError(
                    "forensic_assertion_plan_rebound"
                )
            if _read_exact(
                paths.root,
                evaluation_path,
                sha256=evaluation.sha256,
                size_bytes=len(evaluation.canonical_bytes),
                maximum_bytes=8 * 1024 * 1024,
            ) != evaluation.canonical_bytes:
                raise ForensicAssertionHotPathError(
                    "forensic_assertion_evaluation_rebound"
                )
            recomputed = evaluate_forensic_assertion_execution(
                execution_plan,
                tuple(transports),
                operator_spec_payload=spec_payload,
                current_index_execution=index_execution,
                current_sources=sources,
                current_readiness=readiness,
            )
            if recomputed != evaluation:
                raise ForensicAssertionHotPathError(
                    "forensic_assertion_evaluation_changed"
                )
            validate_forensic_assertion_state_projection(
                projection,
                evaluation=evaluation,
                execution_plan=execution_plan,
                operator_spec_payload=spec_payload,
                existing_global_ids=_safe_projection_ids(
                    final_base,
                    excluding=projection_owned,
                ),
            )

        def append_projection(current: ChallengeState) -> None:
            if (
                current.revision != final_base.revision
                or current.configuration_epoch
                != state.configuration_epoch
                or _all_state_ids(current)
                != _all_state_ids(final_base)
            ):
                raise EngineError(
                    "Forensic assertion state changed before final commit"
                )
            attempts = current.extra.get(
                "forensic_assertion_preissues"
            )
            active = (
                attempts.get(attempt_id)
                if type(attempts) is dict
                else None
            )
            request_states = (
                active.get("requests")
                if type(active) is dict
                else None
            )
            if (
                type(active) is not dict
                or active.get("status") != "running"
                or active.get("terminal") is not None
                or type(request_states) is not list
                or any(
                    request_state.get("status") != "captured"
                    for request_state in request_states
                )
            ):
                raise EngineError(
                    "Forensic assertion preissue is not finalizable"
                )
            validate_forensic_assertion_state_projection(
                projection,
                evaluation=evaluation,
                execution_plan=execution_plan,
                operator_spec_payload=spec_payload,
                existing_global_ids=_safe_projection_ids(
                    current,
                    excluding=projection_owned,
                ),
            )
            preissued_run_ids = {
                request.run_id for request in execution_plan.requests
            }
            preissued_artifact_ids = {
                state_ids.operator_spec_artifact_id,
                state_ids.plan_artifact_id,
                *(
                    request.request_id
                    for request in execution_plan.requests
                ),
            }
            current.runs = [
                run
                for run in current.runs
                if run.id not in preissued_run_ids
            ]
            current.artifacts = [
                artifact
                for artifact in current.artifacts
                if artifact.id not in preissued_artifact_ids
            ]
            current.experiments.append(projection.experiment)
            current.runs.extend(projection.runs)
            current.receipts.extend(projection.receipts)
            current.artifacts.extend(projection.artifacts)
            if projection.fact is not None:
                current.facts.append(projection.fact)
            if projection.progress is not None:
                current.progress_markers.append(projection.progress)
            active["active_run_id"] = None
            active["status"] = "completed"
            active["terminal"] = {
                "at": utc_now(),
                "evaluation_sha256": evaluation.sha256,
                "projection_sha256": projection.sha256,
                "reason_code": (
                    "forensic_assertion_confirmed"
                    if evaluation.confirmed
                    else "forensic_assertion_rejected"
                ),
            }
            validate_forensic_assertion_state_graph(current)

        committed = engine.store.update(
            identity,
            append_projection,
            expected_revision=final_base.revision,
            pre_replace_guard=verify_final,
        )
        validate_forensic_assertion_state_graph(committed)
        return committed, evaluation
    except BaseException as error:
        _terminalize(engine, identity, attempt_id, error)
        raise


__all__ = [
    "FORENSIC_ASSERTION_HOTPATH_PROTOCOL",
    "FORENSIC_ASSERTION_HOTPATH_SCHEMA_VERSION",
    "FORENSIC_ASSERTION_READINESS_PROTOCOL",
    "ForensicAssertionHotPathError",
    "execute_forensic_assertion_hotpath",
]
