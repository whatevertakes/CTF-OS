"""Engine-owned dynamic Pwn interaction proof hot path.

This is deliberately an operator-explicit operation on one already-open
challenge.  It accepts a canonical, data-only interaction recipe only after
reconstructing an existing full-width instruction-pointer-control result,
pre-issues every identity and all six attack/control requests in
``state.json``, and then invokes only the attested image producer against the
original ELF in fresh, networkless proof containers.

The hot path can establish a narrow, executed exploit-effect fact.  It never
changes challenge status, creates a flag candidate, submits a value, chooses
another challenge, or treats a producer self-report as sufficient evidence.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import secrets
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Mapping

from ctf_os.capabilities import REQUIRED_MANAGED_ATTESTATIONS
from ctf_os.contracts.pwn_interaction_v1 import (
    PWN_INTERACTION_V1_CONTRACT_FINGERPRINT,
    PWN_INTERACTION_V1_MAX_DOCUMENT_BYTES,
    PwnInteractionRecipe,
    PwnInteractionRecipeError,
    parse_pwn_interaction_v1_recipe,
)
from ctf_os.director.resources import ResourceVector
from ctf_os.engine.flags import FlagDetector
from ctf_os.flag_formats import resolve_flag_format
from ctf_os.models import (
    ArtifactReference,
    ChallengeIdentity,
    ChallengeState,
    ChallengeStatus,
    ExecutionReceipt,
    Experiment,
    ExperimentKind,
    ExperimentStatus,
    Fact,
    FactKind,
    ProgressMarker,
    Provenance,
    ReceiptOutcome,
    RunOrigin,
    RunReference,
    RunStatus,
    utc_now,
)
from ctf_os.sandbox import NetworkPolicy
from ctf_os.sandbox.files import (
    SafeFileError,
    ensure_private_directory,
    read_bounded_regular,
)
from ctf_os.sandbox.types import CommandSpec, ProofInput, ProofOutput
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.stages.ingest import inventory_challenge
from ctf_os.store import ChallengeLock, LockTimeout
from ctf_os.store.atomic import atomic_write_bytes

if TYPE_CHECKING:
    from ctf_os.engine.challenge import ChallengeEngine
    from ctf_os.engine.pwn_interaction import (
        PwnInteractionEvaluation,
        PwnInteractionReplayEvidence,
    )
    from ctf_os.sandbox import ArtifactRef, SandboxResult


PWN_INTERACTION_HOTPATH_PROTOCOL = "ctfos.pwn.interaction.hotpath.v1"
PWN_INTERACTION_HOTPATH_SCHEMA_VERSION = 1
PWN_INTERACTION_STATE_KEY = "pwn_interaction_preissues"
PWN_INTERACTION_ENGINE_EXECUTOR = "pwn_interaction_v1"
PWN_INTERACTION_CAPABILITY = "pwn_interaction_v1"
PWN_INTERACTION_PRODUCER_PATH = (
    "/opt/ctf-templates/pwn/interaction.py"
)
PWN_INTERACTION_PRODUCER_SHA256 = (
    "d2a5a4370242adb0fae75ac4ddc68ffd"
    "43952e671ba0abc0ad68f1924423b5b9"
)
PWN_INTERACTION_MAX_SOURCE_BYTES = 1024 * 1024 * 1024
PWN_INTERACTION_MAX_RESULT_BYTES = 64 * 1024
PWN_INTERACTION_MAX_STREAM_BYTES = 1024 * 1024
PWN_INTERACTION_MAX_TRANSCRIPT_BYTES = 8 * 1024 * 1024
PWN_INTERACTION_MAX_DAG_BYTES = 1024 * 1024
PWN_INTERACTION_DEFAULT_TIMEOUT_SECONDS = 900
PWN_INTERACTION_MAX_TIMEOUT_SECONDS = 3600

_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CLEAN_STDOUT = re.compile(
    r"^proof/(?P<prefix>clean-[0-9a-f]{12})/stdout\.log$"
)
_OUTPUT_SPECS = (
    ("target.stdout.bin", PWN_INTERACTION_MAX_STREAM_BYTES, "target_stdout"),
    ("target.stderr.bin", PWN_INTERACTION_MAX_STREAM_BYTES, "target_stderr"),
    ("transcript.json", PWN_INTERACTION_MAX_TRANSCRIPT_BYTES, "transcript"),
    ("derivation-dag.json", PWN_INTERACTION_MAX_DAG_BYTES, "derivation_dag"),
)


class PwnInteractionHotPathError(RuntimeError):
    """One stable fail-closed operator-visible hot-path error."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class _ReplayIssue:
    phase: str
    ordinal: int
    experiment_id: str
    run_id: str
    receipt_id: str
    producer_stdout_artifact_id: str
    producer_stderr_artifact_id: str
    output_artifact_ids: tuple[str, str, str, str]


@dataclass(frozen=True, slots=True)
class _ReplayCapture:
    issue: _ReplayIssue
    result: SandboxResult
    scope_fingerprint: str
    clean_prefix: str
    evidence: PwnInteractionReplayEvidence
    artifacts: tuple[ArtifactReference, ...]
    artifact_payloads: tuple[bytes, ...]
    result_path: str
    result_bytes: bytes
    validation_path: str
    validation_bytes: bytes
    wall_seconds: float


def _new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(16)}"


def _canonical_bytes(value: object) -> bytes:
    try:
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
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise PwnInteractionHotPathError(
            "pwn_interaction_canonical_json_invalid"
        ) from error


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


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


def _read_artifact(
    root: Path,
    artifact: ArtifactReference,
    *,
    maximum_bytes: int,
) -> bytes:
    if (
        type(artifact.size) is not int
        or not 0 <= artifact.size <= maximum_bytes
    ):
        raise PwnInteractionHotPathError(
            "pwn_interaction_artifact_size_invalid"
        )
    try:
        return read_bounded_regular(
            root,
            artifact.path,
            maximum_bytes=maximum_bytes,
            expected_sha256=artifact.sha256,
            expected_size=artifact.size,
        )
    except (OSError, SafeFileError, ValueError) as error:
        raise PwnInteractionHotPathError(
            "pwn_interaction_artifact_binding_changed"
        ) from error


def _read_scoped(
    root: Path,
    reference: ArtifactRef,
    *,
    maximum_bytes: int,
) -> bytes:
    try:
        return read_bounded_regular(
            root,
            reference.locator,
            maximum_bytes=maximum_bytes,
            expected_sha256=reference.sha256,
            expected_size=reference.size_bytes,
        )
    except (OSError, SafeFileError, ValueError) as error:
        raise PwnInteractionHotPathError(
            "pwn_interaction_sandbox_artifact_changed"
        ) from error


def _read_unbound_stable_regular(
    root: Path,
    locator: str,
    *,
    maximum_bytes: int,
) -> bytes:
    """Safely establish an initial sidecar hash through one stable fd."""

    from ctf_os.sandbox.files import normalize_locator

    normalized = normalize_locator(locator)
    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    file_flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(root, directory_flags)
    file_fd: int | None = None
    try:
        parts = normalized.split("/")
        for component in parts[:-1]:
            next_fd = os.open(
                component,
                directory_flags,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            parts[-1],
            file_flags,
            dir_fd=directory_fd,
        )
        before = os.fstat(file_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 1
            or before.st_size > maximum_bytes
        ):
            raise SafeFileError(
                "unbound sidecar is not a bounded regular file"
            )
        payload = bytearray()
        while len(payload) <= maximum_bytes:
            block = os.read(
                file_fd,
                min(64 * 1024, maximum_bytes + 1 - len(payload)),
            )
            if not block:
                break
            payload.extend(block)
        after = os.fstat(file_fd)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if (
            len(payload) != before.st_size
            or len(payload) > maximum_bytes
            or any(
                getattr(before, name) != getattr(after, name)
                for name in stable_fields
            )
        ):
            raise SafeFileError(
                "unbound sidecar changed during bounded read"
            )
        return bytes(payload)
    except OSError as error:
        raise SafeFileError(
            "unbound sidecar cannot be opened safely"
        ) from error
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)


def _artifact_from_bytes(
    *,
    artifact_id: str,
    destination: Path,
    root: Path,
    payload: bytes,
    run_id: str | None,
    kind: str,
    attempt_id: str,
    phase: str | None = None,
    ordinal: int | None = None,
) -> ArtifactReference:
    ensure_private_directory(destination.parent)
    atomic_write_bytes(destination, payload, mode=0o400)
    return ArtifactReference(
        id=artifact_id,
        path=destination.relative_to(root).as_posix(),
        sha256=_sha256(payload),
        source_run_id=run_id,
        media_type=(
            "application/json"
            if kind
            in {
                "preissue",
                "evaluation",
                "producer_stdout",
                "transcript",
                "derivation_dag",
            }
            else "application/octet-stream"
        ),
        size=len(payload),
        extra={
            "attempt_id": attempt_id,
            "kind": f"pwn_interaction_{kind}",
            "ordinal": ordinal,
            "phase": phase,
            "protocol": PWN_INTERACTION_HOTPATH_PROTOCOL,
        },
    )


def _complete_transport(result: SandboxResult) -> bool:
    return (
        result.timed_out is False
        and result.status == "completed"
        and type(result.exit_code) is int
        and result.exit_code == 0
        and result.stdout_capture_complete is True
        and result.stderr_capture_complete is True
        and result.stdout_truncation_known is True
        and result.stderr_truncation_known is True
        and result.stdout_truncated is False
        and result.stderr_truncated is False
        and result.stdout_summary_truncated is False
        and result.stderr_summary_truncated is False
        and result.stdout_error is None
        and result.stderr_error is None
        and result.stream_capture_error is None
        and result.orchestration_error is None
    )


def _probe_capability(
    engine: ChallengeEngine,
    image_digest: str,
    *,
    timeout_seconds: float,
) -> None:
    if timeout_seconds <= 0:
        raise PwnInteractionHotPathError(
            "pwn_interaction_deadline_expired"
        )
    report = (
        engine._capability_probe(
            image_digest,
            timeout_seconds=min(30.0, timeout_seconds),
        )
        if engine._capability_probe_accepts_timeout
        else engine._capability_probe(image_digest)
    )
    expected = REQUIRED_MANAGED_ATTESTATIONS[
        PWN_INTERACTION_CAPABILITY
    ]
    if (
        type(report) is not dict
        or report.get("ok") is not True
        or report.get("image_digest") != image_digest
        or PWN_INTERACTION_CAPABILITY
        not in report.get("available", ())
        or type(report.get("attestations")) is not dict
        or report["attestations"].get(PWN_INTERACTION_CAPABILITY)
        != expected
        or report.get("attestation_errors") not in ({}, None)
    ):
        raise PwnInteractionHotPathError(
            "pwn_interaction_capability_unavailable"
        )


def _source_binding(
    engine: ChallengeEngine,
    state: ChallengeState,
    *,
    source_locator: str,
) -> tuple[str, int]:
    try:
        inventory = inventory_challenge(
            engine.challenge_input(state.identity)
        )
    except (OSError, ValueError) as error:
        raise PwnInteractionHotPathError(
            "pwn_interaction_source_inventory_failed"
        ) from error
    source = next(
        (item for item in inventory.files if item.path == source_locator),
        None,
    )
    if (
        source is None
        or source.size <= 0
        or source.size > PWN_INTERACTION_MAX_SOURCE_BYTES
        or state.metadata.get("source_manifest_sha256")
        != inventory.manifest_sha256
    ):
        raise PwnInteractionHotPathError(
            "pwn_interaction_source_binding_invalid"
        )
    return source.sha256, source.size


def _resolve_parent_anchor(
    engine: ChallengeEngine,
    state: ChallengeState,
    parent_experiment_id: str,
) -> tuple[dict[str, object], str]:
    """Resolve a typed IP parent or a physically complete executed anchor.

    The latter is eligibility to run this stronger oracle, not primitive or
    exploit authority.  The interaction producer's own 3+3 differential is
    the only authority created by this hot path.
    """

    from ctf_os.engine.pwn_exploit_effect_hotpath import (
        PwnExploitEffectHotPathError,
        _strict_ip_control_parent,
    )

    try:
        result, inputs = _strict_ip_control_parent(
            engine,
            state,
            parent_experiment_id,
        )
    except PwnExploitEffectHotPathError:
        result = None
        inputs = None
    if result is not None and inputs is not None:
        return (
            {
                "authority": "typed_pwn_ip_control_v1",
                "experiment_id": parent_experiment_id,
                "result_sha256": result.evidence_sha256,
            },
            inputs.disclosure.snapshot_recipe.primary_elf_locator,
        )

    experiment = next(
        (
            item
            for item in state.experiments
            if item.id == parent_experiment_id
        ),
        None,
    )
    if (
        experiment is None
        or experiment.status
        not in {
            ExperimentStatus.COMPLETED,
            ExperimentStatus.KEPT,
        }
        or len(experiment.evidence_run_ids) != 1
        or len(experiment.evidence_receipt_ids) != 1
        or not experiment.artifact_ids
        or type(experiment.evaluation_reason) is not str
        or not experiment.evaluation_reason.strip()
        or type(experiment.result) is not dict
        or set(experiment.result)
        != {"exit_code", "receipt_id", "run_id", "timed_out"}
    ):
        raise PwnInteractionHotPathError(
            "pwn_interaction_parent_execution_anchor_invalid"
        )
    run_id = experiment.evidence_run_ids[0]
    receipt_id = experiment.evidence_receipt_ids[0]
    run = next((item for item in state.runs if item.id == run_id), None)
    receipt = next(
        (item for item in state.receipts if item.id == receipt_id),
        None,
    )
    artifacts = {item.id: item for item in state.artifacts}
    if (
        run is None
        or receipt is None
        or run.status is not RunStatus.COMPLETED
        or run.origin
        not in {RunOrigin.OPERATOR_TOOL, RunOrigin.MANAGED_TOOL}
        or run.extra.get("experiment_id") != experiment.id
        or not all(
            type(path) is str and path
            for path in (
                run.request_path,
                run.result_path,
                run.validation_path,
            )
        )
        or receipt.outcome is not ReceiptOutcome.SUCCEEDED
        or receipt.run_id != run.id
        or receipt.experiment_id != experiment.id
        or receipt.exit_code != 0
        or receipt.stdout_artifact_id not in artifacts
        or receipt.stderr_artifact_id not in artifacts
        or experiment.result
        != {
            "exit_code": 0,
            "receipt_id": receipt.id,
            "run_id": run.id,
            "timed_out": False,
        }
    ):
        raise PwnInteractionHotPathError(
            "pwn_interaction_parent_execution_topology_invalid"
        )
    stream_evidence = receipt.extra.get("stream_evidence")
    if type(stream_evidence) is not dict:
        raise PwnInteractionHotPathError(
            "pwn_interaction_parent_stream_evidence_missing"
        )
    for stream_name in ("stdout", "stderr"):
        stream = stream_evidence.get(stream_name)
        if (
            type(stream) is not dict
            or stream.get("capture_complete") is not True
            or stream.get("truncation_known") is not True
            or stream.get("truncated") is not False
            or stream.get("stream_error_present") is not False
            or stream.get("capture_error_present") is not False
            or stream.get("coverage") != "complete_stream"
        ):
            raise PwnInteractionHotPathError(
                "pwn_interaction_parent_stream_evidence_incomplete"
            )
    stdout_artifact = artifacts[receipt.stdout_artifact_id]
    stderr_artifact = artifacts[receipt.stderr_artifact_id]
    if (
        stdout_artifact.id not in experiment.artifact_ids
        or stderr_artifact.id not in experiment.artifact_ids
        or stdout_artifact.source_run_id != run.id
        or stderr_artifact.source_run_id != run.id
    ):
        raise PwnInteractionHotPathError(
            "pwn_interaction_parent_artifact_topology_invalid"
        )
    root = engine.store.challenge_paths(state.identity).root
    stdout = _read_artifact(
        root,
        stdout_artifact,
        maximum_bytes=16 * 1024 * 1024,
    )
    stderr = _read_artifact(
        root,
        stderr_artifact,
        maximum_bytes=16 * 1024 * 1024,
    )
    if not stdout:
        raise PwnInteractionHotPathError(
            "pwn_interaction_parent_stdout_empty"
        )
    executed_facts = [
        item
        for item in state.facts
        if item.provenance is Provenance.EXECUTED
        and item.source_run_id == run.id
        and item.artifact_id == stdout_artifact.id
    ]
    progress = [
        item
        for item in state.progress_markers
        if item.run_id == run.id
        and stdout_artifact.id in item.artifact_ids
    ]
    if len(executed_facts) != 1 or not progress:
        raise PwnInteractionHotPathError(
            "pwn_interaction_parent_executed_provenance_missing"
        )
    sidecars: dict[str, dict[str, object]] = {}
    for name, locator in (
        ("request", run.request_path),
        ("result", run.result_path),
        ("validation", run.validation_path),
    ):
        try:
            payload = _read_unbound_stable_regular(
                root,
                locator,
                maximum_bytes=256 * 1024,
            )
        except (OSError, SafeFileError, ValueError) as error:
            raise PwnInteractionHotPathError(
                "pwn_interaction_parent_sidecar_invalid"
            ) from error
        if not payload:
            raise PwnInteractionHotPathError(
                "pwn_interaction_parent_sidecar_invalid"
            )
        sidecars[name] = {
            "sha256": _sha256(payload),
            "size_bytes": len(payload),
        }
    source_locator = state.metadata.get("adapter_primary_source")
    source_pin = state.metadata.get("adapter_seed_source_binding")
    if (
        type(source_locator) is not str
        or not source_locator
        or type(source_pin) is not dict
        or source_pin.get("path") != source_locator
        or source_pin.get("manifest_sha256")
        != state.metadata.get("source_manifest_sha256")
    ):
        raise PwnInteractionHotPathError(
            "pwn_interaction_parent_source_anchor_missing"
        )
    return (
        {
            "authority": "canonical_executed_parent_v1",
            "experiment_id": experiment.id,
            "fact_id": executed_facts[0].id,
            "progress_ids": sorted(item.id for item in progress),
            "receipt_id": receipt.id,
            "run_id": run.id,
            "sidecars": sidecars,
            "stderr_sha256": _sha256(stderr),
            "stdout_sha256": _sha256(stdout),
        },
        source_locator,
    )


def _producer_command(
    *,
    source_locator: str,
    source_manifest_sha256: str,
    source_sha256: str,
    source_size_bytes: int,
    recipe: PwnInteractionRecipe,
    recipe_destination: str,
    image_digest: str,
    configuration_epoch: int,
    preissue_sha256: str,
    phase: str,
    ordinal: int,
    command_timeout: int,
    deadline: float,
) -> tuple[CommandSpec, ProofInput, tuple[ProofOutput, ...]]:
    output_root = (
        f".ctf/pwn-interaction-v1/{recipe.sha256}/"
        f"{phase}-{ordinal}"
    )
    proof_outputs = tuple(
        ProofOutput(
            source_locator=f"{output_root}/{name}",
            name=name,
            maximum_bytes=maximum,
        )
        for name, maximum, _kind in _OUTPUT_SPECS
    )
    command = CommandSpec.create(
        (
            "/usr/bin/python3",
            PWN_INTERACTION_PRODUCER_PATH,
            "--binary",
            f"/challenge/{source_locator}",
            "--recipe",
            f"/work/{recipe_destination}",
            "--phase",
            phase,
            "--ordinal",
            str(ordinal),
            "--source-manifest-sha256",
            source_manifest_sha256,
            "--source-sha256",
            source_sha256,
            "--source-size-bytes",
            str(source_size_bytes),
            "--recipe-sha256",
            recipe.sha256,
            "--recipe-size-bytes",
            str(len(recipe.canonical_bytes)),
            "--image-digest",
            image_digest,
            "--configuration-epoch",
            str(configuration_epoch),
            "--preissue-sha256",
            preissue_sha256,
        ),
        timeout_seconds=command_timeout,
        summary_bytes=PWN_INTERACTION_MAX_RESULT_BYTES,
        resource_request=ResourceVector(cpu=1, memory_mib=1024),
        deadline_monotonic_seconds=deadline,
    )
    proof_input = ProofInput(
        source_locator="inputs/recipe.json",
        destination_locator=recipe_destination,
        sha256=recipe.sha256,
        size_bytes=len(recipe.canonical_bytes),
    )
    return command, proof_input, proof_outputs


def prove_pwn_interaction(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    parent_experiment_id: str,
    recipe_locator: str,
    timeout_seconds: int = PWN_INTERACTION_DEFAULT_TIMEOUT_SECONDS,
    _session_owned: bool = False,
) -> tuple[ChallengeState, PwnInteractionEvaluation]:
    """Execute one pre-issued dynamic Pwn exploit interaction matrix."""

    from ctf_os.engine.challenge import EngineError, SessionAlreadyRunning
    from ctf_os.engine.pwn_exploit_effect_hotpath import (
        _prepare_source_snapshot,
        _verify_source_snapshot,
    )
    from ctf_os.engine.pwn_interaction import (
        PwnInteractionExpectedBinding,
        PwnInteractionEvaluationError,
        PwnInteractionReplayEvidence,
        evaluate_pwn_interaction_replays,
    )

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
            return prove_pwn_interaction(
                engine,
                identity,
                parent_experiment_id=parent_experiment_id,
                recipe_locator=recipe_locator,
                timeout_seconds=timeout_seconds,
                _session_owned=True,
            )
        finally:
            lock.release()

    if (
        type(parent_experiment_id) is not str
        or not parent_experiment_id
        or type(recipe_locator) is not str
        or not recipe_locator
        or type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= PWN_INTERACTION_MAX_TIMEOUT_SECONDS
    ):
        raise EngineError("invalid Pwn interaction operator request")

    state = engine.refresh_ingest(identity)
    if (
        state.schema_version < STATE_SCHEMA_VERSION
        or str(state.category).casefold() != "pwn"
        or state.status
        in {
            ChallengeStatus.NEW,
            ChallengeStatus.PAUSED,
            ChallengeStatus.SOLVED,
            ChallengeStatus.ABANDONED,
        }
        or state.primary_target_id is not None
    ):
        raise EngineError(
            "Pwn interaction requires one active local Pwn challenge"
        )
    image_digest = engine.config.runtime.image_digest
    if (
        type(image_digest) is not str
        or _IMAGE_DIGEST.fullmatch(image_digest) is None
    ):
        raise EngineError(
            "Pwn interaction requires a digest-pinned runtime image"
        )
    deadline = time.monotonic() + timeout_seconds
    parent_anchor, source_locator = _resolve_parent_anchor(
        engine,
        state,
        parent_experiment_id,
    )
    manifest_sha256 = str(
        state.metadata.get("source_manifest_sha256", "")
    )
    source_sha256, source_size_bytes = _source_binding(
        engine,
        state,
        source_locator=source_locator,
    )
    if (
        manifest_sha256
        != state.metadata.get("source_manifest_sha256")
    ):
        raise EngineError(
            "Pwn interaction parent and source inventory differ"
        )

    state, recipe_artifact = engine.register_workspace_artifact(
        identity,
        recipe_locator,
    )
    recipe_bytes = _read_artifact(
        engine.store.challenge_paths(identity).root,
        recipe_artifact,
        maximum_bytes=PWN_INTERACTION_V1_MAX_DOCUMENT_BYTES,
    )
    try:
        recipe = parse_pwn_interaction_v1_recipe(recipe_bytes)
    except PwnInteractionRecipeError as error:
        raise EngineError(
            f"invalid bounded Pwn interaction recipe: {error.code}"
        ) from error
    current_parent_anchor, current_source_locator = _resolve_parent_anchor(
        engine,
        state,
        parent_experiment_id,
    )
    if (
        current_source_locator != source_locator
        or current_parent_anchor != parent_anchor
    ):
        raise EngineError(
            "Pwn interaction parent authority changed"
        )
    current_source_sha, current_source_size = _source_binding(
        engine,
        state,
        source_locator=source_locator,
    )
    if (
        current_source_sha != source_sha256
        or current_source_size != source_size_bytes
    ):
        raise EngineError("Pwn interaction source changed")

    _probe_capability(
        engine,
        image_digest,
        timeout_seconds=deadline - time.monotonic(),
    )
    paths = engine.store.challenge_paths(identity)
    attempt_id = _new_id("pwn-interaction")
    experiment_id = _new_id("E-pwn-interaction")
    result_artifact_id = _new_id("A-pwn-interaction-result")
    fact_id = _new_id("F-pwn-interaction")
    progress_id = _new_id("P-pwn-interaction")
    attempt_root = ensure_private_directory(
        paths.artifacts / "pwn-interaction" / attempt_id
    )
    preissue_path = attempt_root / "preissue.json"
    captures_root = ensure_private_directory(
        attempt_root / "captures"
    )
    phases = (("attack", 1), ("attack", 2), ("attack", 3),
              ("control", 1), ("control", 2), ("control", 3))
    issues = tuple(
        _ReplayIssue(
            phase=phase,
            ordinal=ordinal,
            experiment_id=_new_id("E-pwn-interaction-replay"),
            run_id=_new_id("pwn-interaction-run"),
            receipt_id=_new_id("RCPT-pwn-interaction"),
            producer_stdout_artifact_id=_new_id(
                "A-pwn-interaction-producer-stdout"
            ),
            producer_stderr_artifact_id=_new_id(
                "A-pwn-interaction-producer-stderr"
            ),
            output_artifact_ids=tuple(
                _new_id(f"A-pwn-interaction-{kind}")
                for _name, _maximum, kind in _OUTPUT_SPECS
            ),
        )
        for phase, ordinal in phases
    )
    preissue_artifact_id = _new_id("A-pwn-interaction-preissue")
    issued_ids = {
        attempt_id,
        experiment_id,
        preissue_artifact_id,
        result_artifact_id,
        fact_id,
        progress_id,
        *(
            identifier
            for issue in issues
            for identifier in (
                issue.run_id,
                issue.receipt_id,
                issue.experiment_id,
                issue.producer_stdout_artifact_id,
                issue.producer_stderr_artifact_id,
                *issue.output_artifact_ids,
            )
        ),
    }
    if (
        len(issued_ids) != 6 + 9 * len(issues)
        or _all_state_ids(state) & issued_ids
    ):
        raise EngineError(
            "Pwn interaction preissued identity collision"
        )

    before_status = state.status
    before_candidates = tuple(item.id for item in state.candidates)
    before_submissions = tuple(item.id for item in state.submissions)
    before_ids = _all_state_ids(state)
    base_revision = state.revision
    configuration_epoch = state.configuration_epoch
    preissue_document = {
        "attempt_id": attempt_id,
        "capability": copy.deepcopy(
            REQUIRED_MANAGED_ATTESTATIONS[
                PWN_INTERACTION_CAPABILITY
            ]
        ),
        "configuration_epoch": configuration_epoch,
        "contract_fingerprint": (
            PWN_INTERACTION_V1_CONTRACT_FINGERPRINT
        ),
        "experiment_id": experiment_id,
        "image_digest": image_digest,
        "parent_experiment_id": parent_experiment_id,
        "parent_execution_anchor": copy.deepcopy(parent_anchor),
        "protocol": PWN_INTERACTION_HOTPATH_PROTOCOL,
        "recipe": {
            "artifact_id": recipe_artifact.id,
            "sha256": recipe.sha256,
            "size_bytes": len(recipe.canonical_bytes),
        },
        "replays": [
            {
                "ordinal": issue.ordinal,
                "experiment_id": issue.experiment_id,
                "output_artifact_ids": list(
                    issue.output_artifact_ids
                ),
                "phase": issue.phase,
                "producer_stderr_artifact_id": (
                    issue.producer_stderr_artifact_id
                ),
                "producer_stdout_artifact_id": (
                    issue.producer_stdout_artifact_id
                ),
                "receipt_id": issue.receipt_id,
                "run_id": issue.run_id,
            }
            for issue in issues
        ],
        "schema_version": PWN_INTERACTION_HOTPATH_SCHEMA_VERSION,
        "source": {
            "locator": source_locator,
            "manifest_sha256": manifest_sha256,
            "sha256": source_sha256,
            "size_bytes": source_size_bytes,
        },
    }
    preissue_bytes = _canonical_bytes(preissue_document)
    preissue_sha256 = _sha256(preissue_bytes)
    preissue_artifact = _artifact_from_bytes(
        artifact_id=preissue_artifact_id,
        destination=preissue_path,
        root=paths.root,
        payload=preissue_bytes,
        run_id=None,
        kind="preissue",
        attempt_id=attempt_id,
    )
    recipe_destination = (
        ".ctf/pwn-interaction-v1-input/recipe.json"
    )
    recipe_timeout = math.ceil(
        int(recipe.document["timeout_milliseconds"]) / 1000
    )
    command_timeout = max(1, min(135, recipe_timeout + 15))
    commands: list[
        tuple[CommandSpec, ProofInput, tuple[ProofOutput, ...]]
    ] = []
    run_request_bytes: dict[str, bytes] = {}
    run_request_paths: dict[str, str] = {}
    for issue in issues:
        command, proof_input, proof_outputs = _producer_command(
            source_locator=source_locator,
            source_manifest_sha256=manifest_sha256,
            source_sha256=source_sha256,
            source_size_bytes=source_size_bytes,
            recipe=recipe,
            recipe_destination=recipe_destination,
            image_digest=image_digest,
            configuration_epoch=configuration_epoch,
            preissue_sha256=preissue_sha256,
            phase=issue.phase,
            ordinal=issue.ordinal,
            command_timeout=command_timeout,
            deadline=deadline,
        )
        commands.append((command, proof_input, proof_outputs))
        request = {
            "attempt_id": attempt_id,
            "command": {
                "argv": list(command.argv),
                "environment": dict(command.environment),
                "network_target": None,
                "resource_request": {
                    "cpu": command.resource_request.cpu,
                    "gpu": command.resource_request.gpu,
                    "kvm": command.resource_request.kvm,
                    "memory_mib": command.resource_request.memory_mib,
                    "network": command.resource_request.network,
                },
                "summary_bytes": command.summary_bytes,
                "timeout_seconds": command.timeout_seconds,
            },
            "experiment_id": issue.experiment_id,
            "aggregate_experiment_id": experiment_id,
            "preissue_sha256": preissue_sha256,
            "proof_input": proof_input.as_dict(),
            "proof_outputs": [
                item.as_dict() for item in proof_outputs
            ],
            "protocol": PWN_INTERACTION_HOTPATH_PROTOCOL,
            "replay": {
                "ordinal": issue.ordinal,
                "phase": issue.phase,
            },
            "schema_version": PWN_INTERACTION_HOTPATH_SCHEMA_VERSION,
            "transport": {
                "clean_workspace": True,
                "declared_output_count": 4,
                "proof_identity": {
                    "assignment": "post_execution",
                    "fields": [
                        "scope_fingerprint",
                        "sandbox_run_id",
                        "clean_prefix",
                    ],
                },
                "network": "none",
                "one_shot": True,
                "sandbox_method": "run_clean_proof",
            },
        }
        run_paths = engine.store.create_run(
            identity,
            issue.run_id,
            request=request,
            base_revision=base_revision,
        )
        payload = run_paths.request.read_bytes()
        run_request_bytes[issue.run_id] = payload
        run_request_paths[issue.run_id] = (
            run_paths.request.relative_to(paths.root).as_posix()
        )

    journal_preissue = {
        "attempt_id": attempt_id,
        "automatic_submission_authorized": False,
        "candidate_authorized": False,
        "configuration_epoch": configuration_epoch,
        "experiment_id": experiment_id,
        "fact_id": fact_id,
        "image_digest": image_digest,
        "parent_experiment_id": parent_experiment_id,
        "preissue_artifact_id": preissue_artifact_id,
        "preissue_sha256": preissue_sha256,
        "progress_id": progress_id,
        "protocol": PWN_INTERACTION_HOTPATH_PROTOCOL,
        "recipe_artifact_id": recipe_artifact.id,
        "recipe_sha256": recipe.sha256,
        "replays": [
            {
                **preissue_document["replays"][index],
                "request_path": run_request_paths[issue.run_id],
                "request_sha256": _sha256(
                    run_request_bytes[issue.run_id]
                ),
            }
            for index, issue in enumerate(issues)
        ],
        "result_artifact_id": result_artifact_id,
        "schema_version": PWN_INTERACTION_HOTPATH_SCHEMA_VERSION,
        "source": copy.deepcopy(preissue_document["source"]),
        "status": "preissued",
        "terminal": False,
    }
    experiment = Experiment(
        id=experiment_id,
        # Engine-owned probe graphs are evidence operations, not strategic
        # hypothesis actions.  The explicit parent is bound separately.
        hypothesis_ids=[],
        command="engine-owned bounded Pwn interaction producer",
        expected_observation=(
            "three attack sentinels and zero sentinels in three matched "
            "producer-owned effect-address controls"
        ),
        keep_if="the independent host evaluator accepts all exact 3+3 replays",
        drop_if="any binding, transport, transcript, DAG, or differential fails",
        timeout_seconds=timeout_seconds,
        resource_class="heavy",
        kind=ExperimentKind.PROBE,
        status=ExperimentStatus.REGISTERED,
        artifact_ids=[recipe_artifact.id, preissue_artifact_id],
        extra={
            "engine_executor": PWN_INTERACTION_ENGINE_EXECUTOR,
            "parent_experiment_id": parent_experiment_id,
            "pwn_interaction": {
                "attempt_id": attempt_id,
                "preissue_sha256": preissue_sha256,
                "protocol": PWN_INTERACTION_HOTPATH_PROTOCOL,
            },
        },
    )
    preissued_runs = [
        RunReference(
            id=issue.run_id,
            base_revision=base_revision,
            status=RunStatus.CREATED,
            request_path=run_request_paths[issue.run_id],
            role="pwn_interaction",
            origin=RunOrigin.OPERATOR_TOOL,
            configuration_epoch=configuration_epoch,
            extra={
                "pwn_interaction": {
                    "attempt_id": attempt_id,
                    "ordinal": issue.ordinal,
                    "phase": issue.phase,
                    "preissue_sha256": preissue_sha256,
                }
            },
        )
        for issue in issues
    ]
    replay_experiments = [
        Experiment(
            id=issue.experiment_id,
            hypothesis_ids=list(experiment.hypothesis_ids),
            command=(
                "one engine-owned bounded Pwn interaction replay"
            ),
            expected_observation=(
                f"{issue.phase} replay {issue.ordinal} produces a "
                "canonically bound producer document and four artifacts"
            ),
            keep_if="the replay is transport-complete and evaluator-bound",
            drop_if="any request, output, transcript, or DAG binding differs",
            timeout_seconds=timeout_seconds,
            resource_class="heavy",
            kind=ExperimentKind.PROBE,
            status=ExperimentStatus.REGISTERED,
            extra={
                "engine_executor": "pwn_interaction_replay_v1",
                "parent_experiment_id": experiment_id,
                "pwn_interaction": {
                    "attempt_id": attempt_id,
                    "ordinal": issue.ordinal,
                    "phase": issue.phase,
                    "preissue_sha256": preissue_sha256,
                },
            },
        )
        for issue in issues
    ]

    def commit_preissue(current: ChallengeState) -> None:
        if (
            current.revision != base_revision
            or current.configuration_epoch != configuration_epoch
            or current.status is not before_status
            or tuple(item.id for item in current.candidates)
            != before_candidates
            or tuple(item.id for item in current.submissions)
            != before_submissions
            or _all_state_ids(current) != before_ids
        ):
            raise PwnInteractionHotPathError(
                "pwn_interaction_state_changed_before_preissue"
            )
        current_anchor, current_source = _resolve_parent_anchor(
            engine,
            current,
            parent_experiment_id,
        )
        if (
            current_anchor != parent_anchor
            or current_source != source_locator
        ):
            raise PwnInteractionHotPathError(
                "pwn_interaction_parent_changed_before_preissue"
            )
        history = current.extra.setdefault(
            PWN_INTERACTION_STATE_KEY,
            {},
        )
        if type(history) is not dict or attempt_id in history:
            raise PwnInteractionHotPathError(
                "pwn_interaction_preissue_collision"
            )
        current.artifacts.append(copy.deepcopy(preissue_artifact))
        current.experiments.append(copy.deepcopy(experiment))
        current.experiments.extend(
            copy.deepcopy(replay_experiments)
        )
        current.runs.extend(copy.deepcopy(preissued_runs))
        history[attempt_id] = copy.deepcopy(journal_preissue)

    preissued_state = engine.store.update(
        identity,
        commit_preissue,
        expected_revision=base_revision,
    )
    preissued_revision = preissued_state.revision
    private_workspace: tempfile.TemporaryDirectory[str] | None = None
    source_staging: tempfile.TemporaryDirectory[str] | None = None
    lease = None
    captures: list[_ReplayCapture] = []

    def verify_completed_captures() -> None:
        for capture in captures:
            for artifact, expected_payload in zip(
                capture.artifacts,
                capture.artifact_payloads,
                strict=True,
            ):
                try:
                    observed_payload = _read_artifact(
                        paths.root,
                        artifact,
                        maximum_bytes=max(1, len(expected_payload)),
                    )
                except PwnInteractionHotPathError as error:
                    raise PwnInteractionHotPathError(
                        "pwn_interaction_completed_evidence_changed"
                    ) from error
                if observed_payload != expected_payload:
                    raise PwnInteractionHotPathError(
                        "pwn_interaction_completed_evidence_changed"
                    )
            for locator, expected_payload in (
                (capture.result_path, capture.result_bytes),
                (capture.validation_path, capture.validation_bytes),
            ):
                try:
                    observed_payload = read_bounded_regular(
                        paths.root,
                        locator,
                        maximum_bytes=256 * 1024,
                        expected_sha256=_sha256(expected_payload),
                        expected_size=len(expected_payload),
                    )
                except (OSError, SafeFileError, ValueError) as error:
                    raise PwnInteractionHotPathError(
                        "pwn_interaction_completed_evidence_changed"
                    ) from error
                if observed_payload != expected_payload:
                    raise PwnInteractionHotPathError(
                        "pwn_interaction_completed_evidence_changed"
                    )

    def verify_external() -> None:
        current = engine.store.load(identity, recover=False)
        if (
            current.revision != preissued_revision
            or current.configuration_epoch != configuration_epoch
            or current.status is not before_status
            or tuple(item.id for item in current.candidates)
            != before_candidates
            or tuple(item.id for item in current.submissions)
            != before_submissions
            or engine.config.runtime.image_digest != image_digest
            or current.primary_target_id is not None
        ):
            raise PwnInteractionHotPathError(
                "pwn_interaction_runtime_binding_changed"
            )
        current_anchor, current_source = _resolve_parent_anchor(
            engine,
            current,
            parent_experiment_id,
        )
        if (
            current_anchor != parent_anchor
            or current_source != source_locator
        ):
            raise PwnInteractionHotPathError(
                "pwn_interaction_parent_binding_changed"
            )
        observed_sha, observed_size = _source_binding(
            engine,
            current,
            source_locator=source_locator,
        )
        if (
            observed_sha != source_sha256
            or observed_size != source_size_bytes
            or current.metadata.get("source_manifest_sha256")
            != manifest_sha256
        ):
            raise PwnInteractionHotPathError(
                "pwn_interaction_source_changed"
            )
        current_recipe_artifact = next(
            (
                item
                for item in current.artifacts
                if item.id == recipe_artifact.id
            ),
            None,
        )
        current_preissue_artifact = next(
            (
                item
                for item in current.artifacts
                if item.id == preissue_artifact_id
            ),
            None,
        )
        try:
            artifacts_unchanged = (
                current_recipe_artifact is not None
                and current_preissue_artifact is not None
                and _read_artifact(
                    paths.root,
                    current_recipe_artifact,
                    maximum_bytes=(
                        PWN_INTERACTION_V1_MAX_DOCUMENT_BYTES
                    ),
                )
                == recipe_bytes
                and _read_artifact(
                    paths.root,
                    current_preissue_artifact,
                    maximum_bytes=PWN_INTERACTION_MAX_RESULT_BYTES,
                )
                == preissue_bytes
            )
        except PwnInteractionHotPathError as error:
            raise PwnInteractionHotPathError(
                "pwn_interaction_preissue_artifact_changed"
            ) from error
        if not artifacts_unchanged:
            raise PwnInteractionHotPathError(
                "pwn_interaction_preissue_artifact_changed"
            )
        history = current.extra.get(PWN_INTERACTION_STATE_KEY)
        if (
            type(history) is not dict
            or history.get(attempt_id) != journal_preissue
        ):
            raise PwnInteractionHotPathError(
                "pwn_interaction_preissue_state_changed"
            )
        current_runs = {item.id: item for item in current.runs}
        for issue in issues:
            run = current_runs.get(issue.run_id)
            if (
                run is None
                or run.status is not RunStatus.CREATED
                or run.request_path != run_request_paths[issue.run_id]
            ):
                raise PwnInteractionHotPathError(
                    "pwn_interaction_preissued_run_changed"
                )
            try:
                request_payload = read_bounded_regular(
                    paths.root,
                    run.request_path,
                    maximum_bytes=256 * 1024,
                    expected_sha256=_sha256(
                        run_request_bytes[issue.run_id]
                    ),
                    expected_size=len(
                        run_request_bytes[issue.run_id]
                    ),
                )
            except (OSError, SafeFileError, ValueError) as error:
                raise PwnInteractionHotPathError(
                    "pwn_interaction_request_changed"
                ) from error
            if request_payload != run_request_bytes[issue.run_id]:
                raise PwnInteractionHotPathError(
                    "pwn_interaction_request_changed"
                )
        verify_completed_captures()
        _probe_capability(
            engine,
            image_digest,
            timeout_seconds=deadline - time.monotonic(),
        )

    try:
        private_parent = ensure_private_directory(
            paths.runtime / "pwn-interaction-proof"
        )
        private_workspace = tempfile.TemporaryDirectory(
            prefix=f"{attempt_id}-",
            dir=private_parent,
        )
        proof_root = Path(private_workspace.name)
        recipe_input = proof_root / "inputs" / "recipe.json"
        ensure_private_directory(recipe_input.parent)
        atomic_write_bytes(
            recipe_input,
            recipe.canonical_bytes,
            mode=0o400,
        )
        source_staging, challenge_root = _prepare_source_snapshot(
            engine,
            preissued_state,
            source_locator=source_locator,
            source_sha256=source_sha256,
            source_size_bytes=source_size_bytes,
        )
        client = engine.sandbox(
            preissued_state,
            workspace_override=proof_root,
            challenge_dir_override=challenge_root,
            network_policy_override=NetworkPolicy.deny_all(),
        )
        canonical_scope_fingerprint = client.scope_fingerprint
        if (
            type(canonical_scope_fingerprint) is not str
            or re.fullmatch(
                r"[0-9a-f]{64}",
                canonical_scope_fingerprint,
            )
            is None
        ):
            raise PwnInteractionHotPathError(
                "pwn_interaction_scope_binding_invalid"
            )
        lease = engine.lease_broker.acquire(
            commands[0][0].resource_request,
            timeout=max(
                0.0,
                min(30.0, deadline - time.monotonic()),
            ),
            owner=f"{identity.key}:{attempt_id}",
        )
        if lease is None:
            raise EngineError(
                "Pwn interaction resource lease unavailable"
            )
        flag_policy = resolve_flag_format(
            preissued_state,
            engine.config.runtime.flag_patterns,
        )
        detector = FlagDetector(
            flag_policy.patterns,
            callback=lambda detected: engine._on_tool_flag(
                identity,
                detected,
            ),
            suppress_generic_code_noise=flag_policy.source == "runtime",
        )

        evidences: list[PwnInteractionReplayEvidence] = []
        seen_proof_identities: set[tuple[str, str, str]] = set()
        seen_clean_prefixes: set[str] = set()
        for index, (issue, command_bundle) in enumerate(
            zip(issues, commands, strict=True),
            start=1,
        ):
            if deadline - time.monotonic() <= 0:
                raise PwnInteractionHotPathError(
                    "pwn_interaction_deadline_expired"
                )
            verify_external()
            _verify_source_snapshot(
                challenge_root,
                source_locator=source_locator,
                source_sha256=source_sha256,
                source_size_bytes=source_size_bytes,
            )
            try:
                staged_recipe = read_bounded_regular(
                    proof_root,
                    "inputs/recipe.json",
                    maximum_bytes=PWN_INTERACTION_V1_MAX_DOCUMENT_BYTES,
                    expected_sha256=recipe.sha256,
                    expected_size=len(recipe.canonical_bytes),
                )
            except (OSError, SafeFileError, ValueError) as error:
                raise PwnInteractionHotPathError(
                    "pwn_interaction_private_recipe_changed"
                ) from error
            if staged_recipe != recipe.canonical_bytes:
                raise PwnInteractionHotPathError(
                    "pwn_interaction_private_recipe_changed"
                )
            command, proof_input, proof_outputs = command_bundle
            started = time.monotonic()
            result = client.run_clean_proof(
                command,
                proof_inputs=(proof_input,),
                proof_outputs=proof_outputs,
            )
            wall_seconds = max(0.0, time.monotonic() - started)
            if not _complete_transport(result):
                raise PwnInteractionHotPathError(
                    "pwn_interaction_transport_incomplete"
                )
            if len(result.proof_outputs) != len(_OUTPUT_SPECS):
                raise PwnInteractionHotPathError(
                    "pwn_interaction_output_count_invalid"
                )
            producer_stdout_ref = client.register_artifact(
                result.stdout_path.removeprefix("/work/"),
                maximum_bytes=PWN_INTERACTION_MAX_RESULT_BYTES,
            )
            producer_stderr_ref = client.register_artifact(
                result.stderr_path.removeprefix("/work/"),
                maximum_bytes=PWN_INTERACTION_MAX_RESULT_BYTES,
            )
            clean_match = _CLEAN_STDOUT.fullmatch(
                producer_stdout_ref.locator
            )
            clean_prefix = (
                clean_match.group("prefix")
                if clean_match is not None
                else None
            )
            expected_scope = producer_stdout_ref.scope_fingerprint
            if (
                clean_prefix is None
                or producer_stderr_ref.locator
                != f"proof/{clean_prefix}/stderr.log"
                or producer_stderr_ref.scope_fingerprint
                != expected_scope
                or expected_scope != canonical_scope_fingerprint
                or type(result.run_id) is not str
                or not result.run_id
                or any(
                    item.scope_fingerprint != expected_scope
                    for item in result.proof_outputs
                )
                or len(
                    {
                        producer_stdout_ref.locator,
                        producer_stderr_ref.locator,
                        *(item.locator for item in result.proof_outputs),
                    }
                )
                != 6
            ):
                raise PwnInteractionHotPathError(
                    "pwn_interaction_scope_binding_invalid"
                )
            proof_identity = (
                expected_scope,
                result.run_id,
                clean_prefix,
            )
            if proof_identity in seen_proof_identities:
                raise PwnInteractionHotPathError(
                    "pwn_interaction_scope_binding_invalid"
                )
            if clean_prefix in seen_clean_prefixes:
                raise PwnInteractionHotPathError(
                    "pwn_interaction_scope_binding_invalid"
                )
            seen_proof_identities.add(proof_identity)
            seen_clean_prefixes.add(clean_prefix)
            producer_stdout = _read_scoped(
                proof_root,
                producer_stdout_ref,
                maximum_bytes=PWN_INTERACTION_MAX_RESULT_BYTES,
            )
            producer_stderr = _read_scoped(
                proof_root,
                producer_stderr_ref,
                maximum_bytes=PWN_INTERACTION_MAX_RESULT_BYTES,
            )
            output_payloads: list[bytes] = []
            for declared, reference, (
                expected_name,
                maximum_bytes,
                _kind,
            ) in zip(
                proof_outputs,
                result.proof_outputs,
                _OUTPUT_SPECS,
                strict=True,
            ):
                if (
                    declared.name != expected_name
                    or reference.locator
                    != (
                        f"proof/{clean_prefix}/outputs/"
                        f"{expected_name}"
                    )
                ):
                    raise PwnInteractionHotPathError(
                        "pwn_interaction_output_binding_invalid"
                    )
                output_payloads.append(
                    _read_scoped(
                        proof_root,
                        reference,
                        maximum_bytes=maximum_bytes,
                    )
                )
            evidence = PwnInteractionReplayEvidence(
                document_bytes=producer_stdout,
                stdout_bytes=output_payloads[0],
                stderr_bytes=output_payloads[1],
                transcript_bytes=output_payloads[2],
                derivation_dag_bytes=output_payloads[3],
            )
            evidences.append(evidence)
            detector.feed(
                output_payloads[0].decode("utf-8", errors="replace"),
                source=f"{issue.run_id}:target.stdout",
            )
            detector.feed(
                output_payloads[1].decode("utf-8", errors="replace"),
                source=f"{issue.run_id}:target.stderr",
            )

            durable: list[ArtifactReference] = []
            artifact_payloads = (
                (
                    issue.producer_stdout_artifact_id,
                    producer_stdout,
                    "producer_stdout",
                ),
                (
                    issue.producer_stderr_artifact_id,
                    producer_stderr,
                    "producer_stderr",
                ),
                *(
                    (
                        issue.output_artifact_ids[position],
                        output_payloads[position],
                        _OUTPUT_SPECS[position][2],
                    )
                    for position in range(4)
                ),
            )
            for artifact_position, (
                artifact_id,
                payload,
                kind,
            ) in enumerate(artifact_payloads, start=1):
                durable.append(
                    _artifact_from_bytes(
                        artifact_id=artifact_id,
                        destination=(
                            captures_root
                            / f"{index:02d}-{artifact_position:02d}-{kind}.bin"
                        ),
                        root=paths.root,
                        payload=payload,
                        run_id=issue.run_id,
                        kind=kind,
                        attempt_id=attempt_id,
                        phase=issue.phase,
                        ordinal=issue.ordinal,
                    )
                )
            result_document = {
                "artifact_sha256": {
                    item.extra["kind"]: item.sha256
                    for item in durable
                },
                "preissue_sha256": preissue_sha256,
                "protocol": PWN_INTERACTION_HOTPATH_PROTOCOL,
                "transport": {
                    "clean_prefix": clean_prefix,
                    "network": "none",
                    "one_shot": True,
                    "proof_identity": {
                        "clean_prefix": clean_prefix,
                        "sandbox_run_id": result.run_id,
                        "scope_fingerprint": expected_scope,
                    },
                    "sandbox_method": "run_clean_proof",
                    "sandbox_run_id": result.run_id,
                    "scope_fingerprint": expected_scope,
                },
            }
            validation_document = {
                "complete_transport": True,
                "preissue_sha256": preissue_sha256,
                "protocol": PWN_INTERACTION_HOTPATH_PROTOCOL,
                "transport": {
                    "clean_prefix": clean_prefix,
                    "network": "none",
                    "one_shot": True,
                    "proof_identity": {
                        "clean_prefix": clean_prefix,
                        "sandbox_run_id": result.run_id,
                        "scope_fingerprint": expected_scope,
                    },
                    "sandbox_method": "run_clean_proof",
                    "sandbox_run_id": result.run_id,
                    "scope_fingerprint": expected_scope,
                },
            }
            engine.store.write_run_result(
                identity,
                issue.run_id,
                result_document,
            )
            engine.store.write_run_validation(
                identity,
                issue.run_id,
                validation_document,
            )
            run_paths = engine.store.run_paths(identity, issue.run_id)
            result_path = run_paths.result.relative_to(
                paths.root
            ).as_posix()
            validation_path = run_paths.validation.relative_to(
                paths.root
            ).as_posix()
            try:
                result_bytes = _read_unbound_stable_regular(
                    paths.root,
                    result_path,
                    maximum_bytes=256 * 1024,
                )
                validation_bytes = _read_unbound_stable_regular(
                    paths.root,
                    validation_path,
                    maximum_bytes=256 * 1024,
                )
            except (OSError, SafeFileError, ValueError) as error:
                raise PwnInteractionHotPathError(
                    "pwn_interaction_completed_evidence_changed"
                ) from error
            captures.append(
                _ReplayCapture(
                    issue=issue,
                    result=result,
                    scope_fingerprint=expected_scope,
                    clean_prefix=clean_prefix,
                    evidence=evidence,
                    artifacts=tuple(durable),
                    artifact_payloads=tuple(
                        payload
                        for _artifact_id, payload, _kind
                        in artifact_payloads
                    ),
                    result_path=result_path,
                    result_bytes=result_bytes,
                    validation_path=validation_path,
                    validation_bytes=validation_bytes,
                    wall_seconds=wall_seconds,
                )
            )

        binding = PwnInteractionExpectedBinding(
            configuration_epoch=configuration_epoch,
            image_digest=image_digest,
            preissue_sha256=preissue_sha256,
            producer_sha256=PWN_INTERACTION_PRODUCER_SHA256,
            recipe_sha256=recipe.sha256,
            recipe_size_bytes=len(recipe.canonical_bytes),
            source_manifest_sha256=manifest_sha256,
            source_sha256=source_sha256,
            source_size_bytes=source_size_bytes,
        )
        try:
            evaluation = evaluate_pwn_interaction_replays(
                tuple(evidences),
                expected_binding=binding,
                recipe_bytes=recipe.canonical_bytes,
            )
        except PwnInteractionEvaluationError as error:
            raise PwnInteractionHotPathError(
                f"pwn_interaction_evaluation_rejected:{error.code}"
            ) from error
        evaluation_bytes = evaluation.canonical_bytes()
        if (
            len(evaluation_bytes) > PWN_INTERACTION_MAX_RESULT_BYTES
            or evaluation_bytes != _canonical_bytes(
                evaluation.to_dict()
            )
        ):
            raise PwnInteractionHotPathError(
                "pwn_interaction_evaluation_noncanonical"
            )
        evaluation_artifact = _artifact_from_bytes(
            artifact_id=result_artifact_id,
            destination=attempt_root / "evaluation.json",
            root=paths.root,
            payload=evaluation_bytes,
            run_id=issues[-1].run_id,
            kind="evaluation",
            attempt_id=attempt_id,
        )
        evaluated_at = utc_now()
        capture_artifacts = tuple(
            artifact
            for capture in captures
            for artifact in capture.artifacts
        )
        receipt_ids = [item.issue.receipt_id for item in captures]
        run_ids = [item.issue.run_id for item in captures]
        all_artifact_ids = [
            recipe_artifact.id,
            preissue_artifact_id,
            *(item.id for item in capture_artifacts),
            result_artifact_id,
        ]
        proof_identities = [
            {
                "clean_prefix": capture.clean_prefix,
                "sandbox_run_id": capture.result.run_id,
                "scope_fingerprint": capture.scope_fingerprint,
            }
            for capture in captures
        ]
        result_envelope = {
            "canonical_scope_fingerprint": (
                canonical_scope_fingerprint
            ),
            "evaluation": evaluation.to_dict(),
            "evaluation_sha256": _sha256(evaluation_bytes),
            "preissue_sha256": preissue_sha256,
            "proof_identities": copy.deepcopy(proof_identities),
            "protocol": PWN_INTERACTION_HOTPATH_PROTOCOL,
            "unique_proof_identity_count": len(
                {
                    (
                        item["scope_fingerprint"],
                        item["sandbox_run_id"],
                        item["clean_prefix"],
                    )
                    for item in proof_identities
                }
            ),
            "unique_clean_prefix_count": len(
                {item["clean_prefix"] for item in proof_identities}
            ),
        }
        final_journal = {
            **copy.deepcopy(journal_preissue),
            "canonical_scope_fingerprint": (
                canonical_scope_fingerprint
            ),
            "completed_at": evaluated_at,
            "evaluation_artifact_id": result_artifact_id,
            "evaluation_sha256": _sha256(evaluation_bytes),
            "proof_identities": copy.deepcopy(proof_identities),
            "status": "passed" if evaluation.passed else "rejected",
            "terminal": True,
            "unique_proof_identity_count": len(
                {
                    (
                        item["scope_fingerprint"],
                        item["sandbox_run_id"],
                        item["clean_prefix"],
                    )
                    for item in proof_identities
                }
            ),
            "unique_clean_prefix_count": len(
                {item["clean_prefix"] for item in proof_identities}
            ),
        }

        def commit_final(current: ChallengeState) -> None:
            if (
                current.revision != preissued_revision
                or current.status is not before_status
                or tuple(item.id for item in current.candidates)
                != before_candidates
                or tuple(item.id for item in current.submissions)
                != before_submissions
            ):
                raise PwnInteractionHotPathError(
                    "pwn_interaction_state_changed_before_commit"
                )
            history = current.extra.get(PWN_INTERACTION_STATE_KEY)
            if (
                type(history) is not dict
                or history.get(attempt_id) != journal_preissue
            ):
                raise PwnInteractionHotPathError(
                    "pwn_interaction_preissue_changed_before_commit"
                )
            child = next(
                item
                for item in current.experiments
                if item.id == experiment_id
            )
            if child.status is not ExperimentStatus.REGISTERED:
                raise PwnInteractionHotPathError(
                    "pwn_interaction_experiment_changed"
                )
            child.status = (
                ExperimentStatus.COMPLETED
                if evaluation.passed
                else ExperimentStatus.FAILED
            )
            child.result = {
                "pwn_interaction_evidence": copy.deepcopy(
                    result_envelope
                )
            }
            child.artifact_ids = all_artifact_ids
            child.evidence_run_ids = run_ids
            child.evidence_receipt_ids = receipt_ids
            child.evidence_fact_ids = [fact_id] if evaluation.passed else []
            child.evaluation_reason = (
                f"pwn_interaction:{evaluation.reason_code}"
            )[:512]
            child.evaluated_at = evaluated_at
            runs = {item.id: item for item in current.runs}
            experiments = {
                item.id: item for item in current.experiments
            }
            for capture in captures:
                run = runs[capture.issue.run_id]
                if run.status is not RunStatus.CREATED:
                    raise PwnInteractionHotPathError(
                        "pwn_interaction_run_changed"
                    )
                run.status = RunStatus.COMPLETED
                run.result_path = capture.result_path
                run.validation_path = capture.validation_path
                run.extra["pwn_interaction"].update(
                    {
                        "sandbox_run_id": capture.result.run_id,
                        "transport": {
                            "clean_prefix": capture.clean_prefix,
                            "network": "none",
                            "one_shot": True,
                            "proof_identity": {
                                "clean_prefix": capture.clean_prefix,
                                "sandbox_run_id": capture.result.run_id,
                                "scope_fingerprint": (
                                    capture.scope_fingerprint
                                ),
                            },
                            "sandbox_method": "run_clean_proof",
                            "scope_fingerprint": (
                                capture.scope_fingerprint
                            ),
                        },
                        "terminal": True,
                    }
                )
                producer_stdout = capture.artifacts[0]
                producer_stderr = capture.artifacts[1]
                replay_experiment = experiments[
                    capture.issue.experiment_id
                ]
                if (
                    replay_experiment.status
                    is not ExperimentStatus.REGISTERED
                ):
                    raise PwnInteractionHotPathError(
                        "pwn_interaction_replay_experiment_changed"
                    )
                replay_experiment.status = (
                    ExperimentStatus.COMPLETED
                )
                replay_experiment.result = {
                    "pwn_interaction_replay": {
                        "ordinal": capture.issue.ordinal,
                        "phase": capture.issue.phase,
                        "preissue_sha256": preissue_sha256,
                        "proof_identity": {
                            "clean_prefix": capture.clean_prefix,
                            "sandbox_run_id": capture.result.run_id,
                            "scope_fingerprint": (
                                capture.scope_fingerprint
                            ),
                        },
                        "sandbox_run_id": capture.result.run_id,
                    }
                }
                replay_experiment.artifact_ids = [
                    item.id for item in capture.artifacts
                ]
                replay_experiment.evidence_run_ids = [
                    capture.issue.run_id
                ]
                replay_experiment.evidence_receipt_ids = [
                    capture.issue.receipt_id
                ]
                replay_experiment.evaluation_reason = (
                    "pwn_interaction_replay_transport_complete"
                )
                replay_experiment.evaluated_at = evaluated_at
                current.receipts.append(
                    ExecutionReceipt(
                        id=capture.issue.receipt_id,
                        experiment_id=(
                            capture.issue.experiment_id
                        ),
                        run_id=capture.issue.run_id,
                        outcome=ReceiptOutcome.SUCCEEDED,
                        exit_code=capture.result.exit_code,
                        wall_seconds=capture.wall_seconds,
                        stdout_artifact_id=producer_stdout.id,
                        stderr_artifact_id=producer_stderr.id,
                        stdout_bytes=int(
                            producer_stdout.size or 0
                        ),
                        stderr_bytes=int(
                            producer_stderr.size or 0
                        ),
                        preview="",
                        extra={
                            "pwn_interaction": {
                                "artifact_ids": [
                                    item.id
                                    for item in capture.artifacts
                                ],
                                "ordinal": (
                                    capture.issue.ordinal
                                ),
                                "phase": capture.issue.phase,
                                "preissue_sha256": (
                                    preissue_sha256
                                ),
                                "proof_identity": {
                                    "clean_prefix": (
                                        capture.clean_prefix
                                    ),
                                    "sandbox_run_id": (
                                        capture.result.run_id
                                    ),
                                    "scope_fingerprint": (
                                        capture.scope_fingerprint
                                    ),
                                },
                            }
                        },
                    )
                )
            current.artifacts.extend(
                copy.deepcopy(
                    [*capture_artifacts, evaluation_artifact]
                )
            )
            if evaluation.passed:
                authority = {
                    "automatic_submission_authorized": False,
                    "candidate_authorized": False,
                    "evaluation_sha256": _sha256(
                        evaluation_bytes
                    ),
                    "preissue_sha256": preissue_sha256,
                    "protocol": PWN_INTERACTION_HOTPATH_PROTOCOL,
                }
                current.facts.append(
                    Fact(
                        id=fact_id,
                        statement=(
                            "The original Pwn ELF reproduced a dynamic "
                            "producer-owned exploit effect in three attacks "
                            "and rejected it in three matched controls"
                        ),
                        provenance=Provenance.EXECUTED,
                        kind=FactKind.OBSERVATION,
                        challenge_id=current.challenge_id,
                        source_run_id=issues[-1].run_id,
                        artifact_id=result_artifact_id,
                        locator=evaluation_artifact.path,
                        extra=copy.deepcopy(authority),
                    )
                )
                current.progress_markers.append(
                    ProgressMarker(
                        id=progress_id,
                        statement=(
                            "Pwn dynamic interaction exploit-effect gate "
                            "passed 3 attack + 3 matched control replays"
                        ),
                        run_id=issues[-1].run_id,
                        artifact_ids=[
                            result_artifact_id,
                            preissue_artifact_id,
                        ],
                        extra=copy.deepcopy(authority),
                    )
                )
            history[attempt_id] = final_journal

        final_state = engine.store.update(
            identity,
            commit_final,
            expected_revision=preissued_revision,
            commit_guard=verify_external,
            pre_replace_guard=verify_external,
        )
        if (
            final_state.status is not before_status
            or tuple(item.id for item in final_state.candidates)
            != before_candidates
            or tuple(item.id for item in final_state.submissions)
            != before_submissions
        ):
            raise PwnInteractionHotPathError(
                "pwn_interaction_authority_escape"
            )
        return final_state, evaluation
    except BaseException as failure:
        failure_code = getattr(failure, "code", None)
        if type(failure_code) is not str or not failure_code:
            failure_code = (
                "interrupted"
                if not isinstance(failure, Exception)
                else f"exception_{type(failure).__name__}"
            )
        # These are engine-authored immutable snapshots whose original bytes
        # are still held in memory.  Restore only those exact bytes before a
        # tamper failure is terminalized; never bless attacker bytes and
        # never repair immutable challenge input.
        for bound_artifact, expected_payload, maximum_bytes in (
            (
                recipe_artifact,
                recipe_bytes,
                PWN_INTERACTION_V1_MAX_DOCUMENT_BYTES,
            ),
            (
                preissue_artifact,
                preissue_bytes,
                PWN_INTERACTION_MAX_RESULT_BYTES,
            ),
        ):
            try:
                observed_payload = _read_artifact(
                    paths.root,
                    bound_artifact,
                    maximum_bytes=maximum_bytes,
                )
            except PwnInteractionHotPathError:
                observed_payload = None
            if observed_payload != expected_payload:
                atomic_write_bytes(
                    paths.root / bound_artifact.path,
                    expected_payload,
                    mode=0o400,
                )
                if (
                    _read_artifact(
                        paths.root,
                        bound_artifact,
                        maximum_bytes=maximum_bytes,
                    )
                    != expected_payload
                ):
                    failure.add_note(
                        "Pwn interaction immutable snapshot restoration "
                        "failed"
                    )
        # Completed replay sidecars and copied evidence are also
        # engine-authored snapshots.  Preserve their exact held bytes so a
        # later replay cannot make canonical state point at a mutated result.
        for capture in captures:
            for artifact, expected_payload in zip(
                capture.artifacts,
                capture.artifact_payloads,
                strict=True,
            ):
                try:
                    observed_payload = _read_artifact(
                        paths.root,
                        artifact,
                        maximum_bytes=max(1, len(expected_payload)),
                    )
                except PwnInteractionHotPathError:
                    observed_payload = None
                if observed_payload != expected_payload:
                    atomic_write_bytes(
                        paths.root / artifact.path,
                        expected_payload,
                        mode=0o400,
                    )
            for locator, expected_payload in (
                (capture.result_path, capture.result_bytes),
                (capture.validation_path, capture.validation_bytes),
            ):
                try:
                    observed_payload = read_bounded_regular(
                        paths.root,
                        locator,
                        maximum_bytes=256 * 1024,
                        expected_sha256=_sha256(expected_payload),
                        expected_size=len(expected_payload),
                    )
                except (OSError, SafeFileError, ValueError):
                    observed_payload = None
                if observed_payload != expected_payload:
                    atomic_write_bytes(
                        paths.root / locator,
                        expected_payload,
                        mode=0o400,
                    )
        try:
            verify_completed_captures()
        except PwnInteractionHotPathError as restoration_error:
            failure.add_note(
                "Pwn interaction completed evidence restoration failed: "
                f"{restoration_error.code}"
            )
        failure_document = {
            "attempt_id": attempt_id,
            "completed_replays": len(captures),
            "failure_code": failure_code[:256],
            "preissue_sha256": preissue_sha256,
            "proof_identities": [
                {
                    "clean_prefix": capture.clean_prefix,
                    "sandbox_run_id": capture.result.run_id,
                    "scope_fingerprint": capture.scope_fingerprint,
                }
                for capture in captures
            ],
            "protocol": PWN_INTERACTION_HOTPATH_PROTOCOL,
            "reason_code": failure_code[:256],
            "schema_version": PWN_INTERACTION_HOTPATH_SCHEMA_VERSION,
            "terminal": True,
        }
        failure_bytes = _canonical_bytes(failure_document)
        failure_artifact = _artifact_from_bytes(
            artifact_id=result_artifact_id,
            destination=attempt_root / "failure.json",
            root=paths.root,
            payload=failure_bytes,
            run_id=(
                captures[-1].issue.run_id if captures else None
            ),
            kind="evaluation",
            attempt_id=attempt_id,
        )
        captured_by_run = {
            item.issue.run_id: item for item in captures
        }
        for issue in issues:
            if issue.run_id in captured_by_run:
                continue
            engine.store.write_run_result(
                identity,
                issue.run_id,
                {
                    "failure_code": failure_code[:256],
                    "preissue_sha256": preissue_sha256,
                    "protocol": PWN_INTERACTION_HOTPATH_PROTOCOL,
                    "terminal": True,
                },
            )
            engine.store.write_run_validation(
                identity,
                issue.run_id,
                {
                    "complete_transport": False,
                    "failure_code": failure_code[:256],
                    "preissue_sha256": preissue_sha256,
                    "protocol": PWN_INTERACTION_HOTPATH_PROTOCOL,
                },
            )
        failed_at = utc_now()
        captured_artifacts = tuple(
            artifact
            for capture in captures
            for artifact in capture.artifacts
        )

        def commit_failure(current: ChallengeState) -> None:
            if (
                current.revision != preissued_revision
                or current.status is not before_status
                or tuple(item.id for item in current.candidates)
                != before_candidates
                or tuple(item.id for item in current.submissions)
                != before_submissions
            ):
                raise PwnInteractionHotPathError(
                    "pwn_interaction_failure_state_changed"
                )
            history = current.extra.get(PWN_INTERACTION_STATE_KEY)
            if (
                type(history) is not dict
                or history.get(attempt_id) != journal_preissue
            ):
                raise PwnInteractionHotPathError(
                    "pwn_interaction_failure_preissue_changed"
                )
            experiments = {
                item.id: item for item in current.experiments
            }
            aggregate = experiments[experiment_id]
            if aggregate.status is not ExperimentStatus.REGISTERED:
                raise PwnInteractionHotPathError(
                    "pwn_interaction_failure_experiment_changed"
                )
            aggregate.status = ExperimentStatus.FAILED
            aggregate.result = {
                "pwn_interaction_failure": copy.deepcopy(
                    failure_document
                )
            }
            aggregate.artifact_ids = [
                recipe_artifact.id,
                preissue_artifact_id,
                *(item.id for item in captured_artifacts),
                result_artifact_id,
            ]
            aggregate.evidence_run_ids = [
                item.run_id for item in issues
            ]
            aggregate.evidence_receipt_ids = [
                item.receipt_id for item in issues
            ]
            aggregate.evaluation_reason = (
                f"pwn_interaction:{failure_code}"
            )[:512]
            aggregate.evaluated_at = failed_at
            runs = {item.id: item for item in current.runs}
            for issue in issues:
                run = runs[issue.run_id]
                replay = experiments[issue.experiment_id]
                capture = captured_by_run.get(issue.run_id)
                run_paths = engine.store.run_paths(
                    identity,
                    issue.run_id,
                )
                if (
                    run.status is not RunStatus.CREATED
                    or replay.status
                    is not ExperimentStatus.REGISTERED
                ):
                    raise PwnInteractionHotPathError(
                        "pwn_interaction_failure_replay_changed"
                    )
                run.result_path = run_paths.result.relative_to(
                    paths.root
                ).as_posix()
                run.validation_path = run_paths.validation.relative_to(
                    paths.root
                ).as_posix()
                run.extra["pwn_interaction"].update(
                    {
                        "failure_code": failure_code[:256],
                        "terminal": True,
                    }
                )
                if capture is not None:
                    run.status = RunStatus.COMPLETED
                    replay.status = ExperimentStatus.COMPLETED
                    replay.result = {
                        "pwn_interaction_replay": {
                            "ordinal": issue.ordinal,
                            "phase": issue.phase,
                            "preissue_sha256": preissue_sha256,
                            "proof_identity": {
                                "clean_prefix": (
                                    capture.clean_prefix
                                ),
                                "sandbox_run_id": (
                                    capture.result.run_id
                                ),
                                "scope_fingerprint": (
                                    capture.scope_fingerprint
                                ),
                            },
                            "sandbox_run_id": capture.result.run_id,
                        }
                    }
                    replay.artifact_ids = [
                        item.id for item in capture.artifacts
                    ]
                    replay.evaluation_reason = (
                        "pwn_interaction_replay_transport_complete"
                    )
                    stdout_artifact = capture.artifacts[0]
                    stderr_artifact = capture.artifacts[1]
                    receipt = ExecutionReceipt(
                        id=issue.receipt_id,
                        experiment_id=issue.experiment_id,
                        run_id=issue.run_id,
                        outcome=ReceiptOutcome.SUCCEEDED,
                        exit_code=capture.result.exit_code,
                        wall_seconds=capture.wall_seconds,
                        stdout_artifact_id=stdout_artifact.id,
                        stderr_artifact_id=stderr_artifact.id,
                        stdout_bytes=int(
                            stdout_artifact.size or 0
                        ),
                        stderr_bytes=int(
                            stderr_artifact.size or 0
                        ),
                        preview="",
                        extra={
                            "pwn_interaction": {
                                "artifact_ids": [
                                    item.id
                                    for item in capture.artifacts
                                ],
                                "ordinal": issue.ordinal,
                                "phase": issue.phase,
                                "preissue_sha256": preissue_sha256,
                                "proof_identity": {
                                    "clean_prefix": (
                                        capture.clean_prefix
                                    ),
                                    "sandbox_run_id": (
                                        capture.result.run_id
                                    ),
                                    "scope_fingerprint": (
                                        capture.scope_fingerprint
                                    ),
                                },
                            }
                        },
                    )
                else:
                    run.status = RunStatus.INTERRUPTED
                    replay.status = ExperimentStatus.FAILED
                    replay.result = {
                        "pwn_interaction_replay_failure": {
                            "failure_code": failure_code[:256],
                            "ordinal": issue.ordinal,
                            "phase": issue.phase,
                            "preissue_sha256": preissue_sha256,
                        }
                    }
                    replay.evaluation_reason = (
                        f"pwn_interaction_replay:{failure_code}"
                    )[:512]
                    receipt = ExecutionReceipt(
                        id=issue.receipt_id,
                        experiment_id=issue.experiment_id,
                        run_id=issue.run_id,
                        outcome=ReceiptOutcome.INTERRUPTED,
                        exit_code=None,
                        wall_seconds=0.0,
                        preview="",
                        extra={
                            "pwn_interaction": {
                                "artifact_ids": [],
                                "failure_code": failure_code[:256],
                                "ordinal": issue.ordinal,
                                "phase": issue.phase,
                                "preissue_sha256": preissue_sha256,
                            }
                        },
                    )
                replay.evidence_run_ids = [issue.run_id]
                replay.evidence_receipt_ids = [issue.receipt_id]
                replay.evaluated_at = failed_at
                current.receipts.append(receipt)
            current.artifacts.extend(
                copy.deepcopy(
                    [*captured_artifacts, failure_artifact]
                )
            )
            history[attempt_id] = {
                **copy.deepcopy(journal_preissue),
                "completed_at": failed_at,
                "completed_replays": len(captures),
                "failure_code": failure_code[:256],
                "failure_artifact_id": result_artifact_id,
                "failure_sha256": _sha256(failure_bytes),
                "proof_identities": [
                    {
                        "clean_prefix": capture.clean_prefix,
                        "sandbox_run_id": capture.result.run_id,
                        "scope_fingerprint": (
                            capture.scope_fingerprint
                        ),
                    }
                    for capture in captures
                ],
                "reason_code": failure_code[:256],
                "status": "failed",
                "terminal": True,
            }

        try:
            engine.store.update(
                identity,
                commit_failure,
                expected_revision=preissued_revision,
                commit_guard=verify_completed_captures,
                pre_replace_guard=verify_completed_captures,
            )
        except BaseException as terminal_error:
            failure.add_note(
                "Pwn interaction terminalization failed: "
                f"{type(terminal_error).__name__}: {terminal_error}"
            )
        raise
    finally:
        active_error = __import__("sys").exception()
        cleanup_errors: list[BaseException] = []
        if lease is not None:
            try:
                lease.release()
            except BaseException as error:
                cleanup_errors.append(error)
        if source_staging is not None:
            try:
                source_staging.cleanup()
            except BaseException as error:
                cleanup_errors.append(error)
        if private_workspace is not None:
            try:
                private_workspace.cleanup()
            except BaseException as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            if active_error is not None:
                for error in cleanup_errors:
                    active_error.add_note(
                        "Pwn interaction cleanup failed: "
                        f"{type(error).__name__}: {error}"
                    )
            else:
                raise cleanup_errors[0]


__all__ = [
    "PWN_INTERACTION_CAPABILITY",
    "PWN_INTERACTION_ENGINE_EXECUTOR",
    "PWN_INTERACTION_HOTPATH_PROTOCOL",
    "PWN_INTERACTION_PRODUCER_PATH",
    "PWN_INTERACTION_PRODUCER_SHA256",
    "PWN_INTERACTION_STATE_KEY",
    "PwnInteractionHotPathError",
    "prove_pwn_interaction",
]
