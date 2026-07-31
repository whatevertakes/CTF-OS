"""Managed-only execution hot path for Crypto/Misc data transcripts.

The Builder contributes one canonical, data-only send/expect recipe.  The
operator contributes a peer and its reset seed through the existing
``managed_oracle_preissue_v1`` state machine.  This module consumes that
preissue before execution and runs the pinned image producer in six separate,
network-denied clean proof workspaces.

Raw peer streams remain engine-private artifacts.  State records contain only
bounded commitments, run topology, and the independent host evaluation.  This
operation never creates a flag candidate, changes submission state, or
authorizes automatic submission.
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
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ctf_os.adapters.base import get_adapter
from ctf_os.capabilities import REQUIRED_MANAGED_ATTESTATIONS
from ctf_os.codex.contracts import MANAGED_DATA_TRANSCRIPT_ACTION_KIND
from ctf_os.contracts.data_transcript_v1 import (
    DATA_TRANSCRIPT_V1_CONTRACT_FINGERPRINT,
    DATA_TRANSCRIPT_V1_MAX_DOCUMENT_BYTES,
    DataTranscriptContractError,
    data_transcript_v1_reset_commitment_sha256,
    parse_data_transcript_v1_recipe,
)
from ctf_os.director.resources import ResourceVector
from ctf_os.engine.data_transcript import (
    DATA_TRANSCRIPT_MAX_HISTORY,
    DATA_TRANSCRIPT_MAX_RESET_PROOF_BYTES,
    DATA_TRANSCRIPT_MAX_RESULT_BYTES,
    DATA_TRANSCRIPT_MAX_STREAM_BYTES,
    DATA_TRANSCRIPT_MAX_TRANSCRIPT_BYTES,
    DATA_TRANSCRIPT_STATE_KEY,
    DataTranscriptEvaluation,
    DataTranscriptEvaluationError,
    DataTranscriptExpectedBinding,
    DataTranscriptReplayEvidence,
    evaluate_data_transcript_replays,
)
from ctf_os.engine.managed_oracle_preissue import (
    MANAGED_ORACLE_PREISSUE_CRYPTO_TRANSCRIPT,
    MANAGED_ORACLE_PREISSUE_MISC_TRANSCRIPT,
    MANAGED_ORACLE_PREISSUE_PROTOCOL,
    MANAGED_ORACLE_PREISSUE_STATE_KEY,
    ManagedOraclePreissueError,
    validate_public_record,
)
from ctf_os.models import (
    ArtifactReference,
    ChallengeIdentity,
    ChallengeState,
    ChallengeStatus,
    ExperimentStatus,
    RunOrigin,
    RunReference,
    RunStatus,
    utc_now,
)
from ctf_os.sandbox import NetworkPolicy
from ctf_os.sandbox.files import (
    SafeFileError,
    copy_bounded_regular,
    ensure_private_directory,
    read_bounded_regular,
)
from ctf_os.sandbox.types import (
    ArtifactRef,
    CommandSpec,
    ProofInput,
    ProofOutput,
    SandboxResult,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.stages.ingest import inventory_challenge
from ctf_os.store import ChallengeLock, LockTimeout, RevisionConflict
from ctf_os.store.atomic import atomic_write_bytes

if TYPE_CHECKING:
    from ctf_os.engine.challenge import ChallengeEngine


DATA_TRANSCRIPT_HOTPATH_PROTOCOL = (
    "ctfos.data_transcript.hotpath.v1"
)
DATA_TRANSCRIPT_HOTPATH_SCHEMA_VERSION = 1
DATA_TRANSCRIPT_CAPABILITY = "data_transcript_v1"
DATA_TRANSCRIPT_PRODUCER_PATH = (
    "/opt/ctf-templates/common/data_transcript.py"
)
DATA_TRANSCRIPT_PRODUCER_SHA256 = (
    "a0e5402456ba09f08429b016329900473"
    "66ca2680be5be52c0f308ef73e74788"
)
DATA_TRANSCRIPT_RESOURCE = ResourceVector(cpu=1, memory_mib=1024)

_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CLEAN_STDOUT = re.compile(
    r"^proof/(?P<prefix>clean-[0-9a-f]{12})/stdout\.log$"
)
_OUTPUT_SPECS = (
    (
        "peer.stdout.bin",
        DATA_TRANSCRIPT_MAX_STREAM_BYTES,
        "peer_stdout",
    ),
    (
        "peer.stderr.bin",
        DATA_TRANSCRIPT_MAX_STREAM_BYTES,
        "peer_stderr",
    ),
    (
        "transcript.json",
        DATA_TRANSCRIPT_MAX_TRANSCRIPT_BYTES,
        "transcript",
    ),
    (
        "reset-proof.json",
        DATA_TRANSCRIPT_MAX_RESET_PROOF_BYTES,
        "reset_proof",
    ),
)
_INACTIVE_STATUSES = frozenset(
    {
        ChallengeStatus.NEW,
        ChallengeStatus.PAUSED,
        ChallengeStatus.SOLVED,
        ChallengeStatus.ABANDONED,
        ChallengeStatus.PROVING,
        ChallengeStatus.READY_TO_SUBMIT,
    }
)


class DataTranscriptHotPathError(RuntimeError):
    """Stable fail-closed rejection from the execution hot path."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class _ReplayIssue:
    phase: str
    ordinal: int
    run_id: str
    artifact_ids: tuple[str, str, str, str, str, str]
    sidecar_artifact_ids: tuple[str, str, str]


@dataclass(frozen=True, slots=True)
class _ReplayCapture:
    issue: _ReplayIssue
    sandbox_run_id: str
    clean_prefix: str
    scope_fingerprint: str
    result_path: str
    validation_path: str
    result_bytes: bytes
    validation_bytes: bytes
    result_artifact: ArtifactReference
    validation_artifact: ArtifactReference
    evidence: DataTranscriptReplayEvidence
    artifacts: tuple[ArtifactReference, ...]
    artifact_payloads: tuple[bytes, ...]


def _artifact_binding(
    artifact: ArtifactReference,
) -> dict[str, object]:
    if artifact.size is None:
        _fail("data_transcript_artifact_size_missing")
    return {
        "artifact_id": artifact.id,
        "path": artifact.path,
        "sha256": artifact.sha256,
        "size_bytes": artifact.size,
    }


def _sidecar_artifact(
    *,
    artifact_id: str,
    path: str,
    payload: bytes,
    run_id: str,
    kind: str,
    attempt_id: str,
    phase: str,
    ordinal: int,
) -> ArtifactReference:
    return ArtifactReference(
        id=artifact_id,
        path=path,
        sha256=_sha256(payload),
        source_run_id=run_id,
        media_type="application/json",
        size=len(payload),
        extra={
            "attempt_id": attempt_id,
            "context_visibility": "engine_private",
            "kind": f"data_transcript_{kind}",
            "ordinal": ordinal,
            "phase": phase,
            "protocol": DATA_TRANSCRIPT_HOTPATH_PROTOCOL,
        },
    )


def _write_exact_run_sidecars(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    issue: _ReplayIssue,
    *,
    attempt_id: str,
    result_document: dict[str, object],
    validation_document: dict[str, object],
) -> tuple[
    str,
    str,
    bytes,
    bytes,
    ArtifactReference,
    ArtifactReference,
]:
    run_paths = engine.store.run_paths(identity, issue.run_id)
    result_bytes = _canonical_bytes(result_document)
    validation_bytes = _canonical_bytes(validation_document)
    engine._enforce_storage_admission(
        identity,
        requested_bytes=len(result_bytes),
    )
    atomic_write_bytes(run_paths.result, result_bytes, mode=0o400)
    engine._enforce_storage_admission(
        identity,
        requested_bytes=len(validation_bytes),
    )
    atomic_write_bytes(
        run_paths.validation,
        validation_bytes,
        mode=0o400,
    )
    root = engine.store.challenge_paths(identity).root
    result_path = run_paths.result.relative_to(root).as_posix()
    validation_path = run_paths.validation.relative_to(root).as_posix()
    result_artifact = _sidecar_artifact(
        artifact_id=issue.sidecar_artifact_ids[1],
        path=result_path,
        payload=result_bytes,
        run_id=issue.run_id,
        kind="result",
        attempt_id=attempt_id,
        phase=issue.phase,
        ordinal=issue.ordinal,
    )
    validation_artifact = _sidecar_artifact(
        artifact_id=issue.sidecar_artifact_ids[2],
        path=validation_path,
        payload=validation_bytes,
        run_id=issue.run_id,
        kind="validation",
        attempt_id=attempt_id,
        phase=issue.phase,
        ordinal=issue.ordinal,
    )
    return (
        result_path,
        validation_path,
        result_bytes,
        validation_bytes,
        result_artifact,
        validation_artifact,
    )


def _typed_gate_result(
    *,
    passed: bool,
    reason_codes: tuple[str, ...],
    evaluation_sha256: str | None,
    evidence_artifact_ids: tuple[str, ...],
    evidence_run_ids: tuple[str, ...],
    execution_error_type: str | None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "action_kind": MANAGED_DATA_TRANSCRIPT_ACTION_KIND,
        "authority": "engine_deterministic_gate",
        "passed": passed,
        "reason_codes": list(reason_codes),
        "evaluation_sha256": evaluation_sha256,
        "evidence_artifact_ids": list(evidence_artifact_ids),
        "evidence_run_ids": list(evidence_run_ids),
        "execution_error_type": execution_error_type,
    }


def _terminalize_parent_experiment(
    state: ChallengeState,
    *,
    experiment_id: str,
    builder_run_id: str,
    completed_at: str,
    passed: bool,
    result: dict[str, object],
) -> None:
    matches = [
        item for item in state.experiments if item.id == experiment_id
    ]
    if (
        len(matches) != 1
        or matches[0].status is not ExperimentStatus.RUNNING
        or matches[0].source_run_id != builder_run_id
    ):
        _fail("data_transcript_parent_experiment_changed")
    target = matches[0]
    target.status = (
        ExperimentStatus.COMPLETED
        if passed
        else ExperimentStatus.FAILED
    )
    evidence_ids = result.get("evidence_artifact_ids")
    if type(evidence_ids) is not list:
        _fail("data_transcript_parent_result_invalid")
    target.artifact_ids = list(
        dict.fromkeys((*target.artifact_ids, *evidence_ids))
    )
    target.result = copy.deepcopy(result)
    target.extra["completed_at"] = completed_at


def _fail(code: str) -> None:
    raise DataTranscriptHotPathError(code)


def _new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(16)}"


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _failure_code(failure: BaseException) -> str:
    code = getattr(failure, "code", None)
    if type(code) is str and code:
        return code[:160]
    if not isinstance(failure, Exception):
        return "interrupted"
    return f"exception_{type(failure).__name__[:96]}"


def _durable_remove_run_directory(
    runs_root: Path,
    run_id: str,
) -> None:
    """Remove one exact fixed-topology run without following links."""

    if re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", run_id) is None:
        raise OSError("unsafe data transcript run id")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    runs_fd: int | None = None
    run_fd: int | None = None
    raw_fd: int | None = None
    try:
        runs_fd = os.open(runs_root, directory_flags)
        try:
            before = os.stat(
                run_id,
                dir_fd=runs_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        if not stat.S_ISDIR(before.st_mode):
            raise OSError(
                "data transcript run cleanup target is not a directory"
            )
        run_fd = os.open(run_id, directory_flags, dir_fd=runs_fd)
        opened = os.fstat(run_fd)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            raise OSError(
                "data transcript run cleanup target changed while opening"
            )
        allowed = {
            "raw",
            "request.json",
            "result.json",
            "validation.json",
        }
        if set(os.listdir(run_fd)) - allowed:
            raise OSError(
                "data transcript run cleanup target has unexpected entries"
            )
        for name in ("validation.json", "result.json", "request.json"):
            try:
                metadata = os.stat(
                    name,
                    dir_fd=run_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError(
                    "data transcript run cleanup leaf is not regular"
                )
            os.unlink(name, dir_fd=run_fd)
        try:
            raw_before = os.stat(
                "raw",
                dir_fd=run_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            raw_before = None
        if raw_before is not None:
            if not stat.S_ISDIR(raw_before.st_mode):
                raise OSError(
                    "data transcript raw cleanup target is not a directory"
                )
            raw_fd = os.open("raw", directory_flags, dir_fd=run_fd)
            raw_opened = os.fstat(raw_fd)
            if (
                (raw_opened.st_dev, raw_opened.st_ino)
                != (raw_before.st_dev, raw_before.st_ino)
                or os.listdir(raw_fd)
            ):
                raise OSError(
                    "data transcript raw cleanup target changed or is not empty"
                )
            os.close(raw_fd)
            raw_fd = None
            os.rmdir("raw", dir_fd=run_fd)
        if os.listdir(run_fd):
            raise OSError(
                "data transcript run cleanup target is not empty"
            )
        os.fsync(run_fd)
        after = os.stat(
            run_id,
            dir_fd=runs_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(after.st_mode)
            or (after.st_dev, after.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            raise OSError(
                "data transcript run cleanup target changed before removal"
            )
        os.close(run_fd)
        run_fd = None
        os.rmdir(run_id, dir_fd=runs_fd)
        os.fsync(runs_fd)
    finally:
        for descriptor in (raw_fd, run_fd, runs_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _cleanup_uncommitted_run_directories(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    run_ids: tuple[str, ...],
) -> None:
    unique_ids = tuple(dict.fromkeys(run_ids))
    if len(unique_ids) > 6:
        _fail("data_transcript_run_cleanup_set_invalid")
    if not unique_ids:
        return
    canonical = engine.store.load(identity, recover=False)
    canonical_ids = {item.id for item in canonical.runs}
    runs_root = engine.store.challenge_paths(identity).runs
    for run_id in unique_ids:
        if run_id not in canonical_ids:
            _durable_remove_run_directory(runs_root, run_id)


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
        raise DataTranscriptHotPathError(
            "data_transcript_canonical_json_invalid"
        ) from error


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
        _fail("data_transcript_artifact_size_invalid")
    try:
        return read_bounded_regular(
            root,
            artifact.path,
            maximum_bytes=maximum_bytes,
            expected_sha256=artifact.sha256,
            expected_size=artifact.size,
        )
    except (OSError, SafeFileError, ValueError) as error:
        raise DataTranscriptHotPathError(
            "data_transcript_artifact_changed"
        ) from error


def _resolve_pinned_recipe(
    state: ChallengeState,
    *,
    challenge_root: Path,
    workspace_root: Path,
    recipe_locator: str,
    recipe_artifact_id: str,
    recipe_sha256: str,
    recipe_size_bytes: int,
    builder_run_id: str,
) -> tuple[ArtifactReference, bytes]:
    """Read the managed snapshot and live workspace under one exact pin."""

    matches = [
        item
        for item in state.artifacts
        if item.id == recipe_artifact_id
    ]
    if len(matches) != 1:
        _fail("data_transcript_recipe_artifact_binding_invalid")
    artifact = matches[0]
    if (
        artifact.sha256 != recipe_sha256
        or artifact.size != recipe_size_bytes
        or artifact.source_run_id != builder_run_id
        or artifact.extra.get("reported_locator") != recipe_locator
    ):
        _fail("data_transcript_recipe_artifact_binding_invalid")
    snapshot_bytes = _read_artifact(
        challenge_root,
        artifact,
        maximum_bytes=DATA_TRANSCRIPT_V1_MAX_DOCUMENT_BYTES,
    )
    try:
        workspace_bytes = read_bounded_regular(
            workspace_root,
            recipe_locator,
            maximum_bytes=DATA_TRANSCRIPT_V1_MAX_DOCUMENT_BYTES,
            expected_sha256=recipe_sha256,
            expected_size=recipe_size_bytes,
        )
    except (OSError, SafeFileError, ValueError) as error:
        raise DataTranscriptHotPathError(
            "data_transcript_workspace_recipe_changed"
        ) from error
    if workspace_bytes != snapshot_bytes:
        _fail("data_transcript_workspace_recipe_changed")
    return artifact, snapshot_bytes


def _reservation_run_ids(
    reservation: dict[str, object],
) -> tuple[str, ...]:
    replays = reservation.get("replays")
    if type(replays) is not list or len(replays) != 6:
        _fail("data_transcript_reservation_invalid")
    run_ids: list[str] = []
    artifact_ids: set[str] = set()
    sidecar_artifact_ids: set[str] = set()
    expected_phases = (
        ("positive", 1),
        ("positive", 2),
        ("positive", 3),
        ("control", 1),
        ("control", 2),
        ("control", 3),
    )
    for replay, expected in zip(replays, expected_phases, strict=True):
        if (
            type(replay) is not dict
            or set(replay)
            != {
                "artifact_ids",
                "ordinal",
                "phase",
                "run_id",
                "sidecar_artifact_ids",
            }
            or (replay.get("phase"), replay.get("ordinal")) != expected
            or type(replay.get("run_id")) is not str
            or not replay["run_id"]
            or type(replay.get("artifact_ids")) is not list
            or len(replay["artifact_ids"]) != 6
            or any(
                type(item) is not str or not item
                for item in replay["artifact_ids"]
            )
            or type(replay.get("sidecar_artifact_ids")) is not dict
            or set(replay["sidecar_artifact_ids"])
            != {"request", "result", "validation"}
            or any(
                type(item) is not str or not item
                for item in replay["sidecar_artifact_ids"].values()
            )
        ):
            _fail("data_transcript_reservation_invalid")
        run_ids.append(replay["run_id"])
        artifact_ids.update(replay["artifact_ids"])
        sidecar_artifact_ids.update(
            replay["sidecar_artifact_ids"].values()
        )
    if (
        len(set(run_ids)) != 6
        or len(artifact_ids) != 36
        or len(sidecar_artifact_ids) != 18
        or artifact_ids & sidecar_artifact_ids
    ):
        _fail("data_transcript_reservation_invalid")
    return tuple(run_ids)


def _validate_reserved_attempt_state(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    state: ChallengeState,
    reservation: dict[str, object],
) -> tuple[str, ...]:
    attempt_id = reservation.get("attempt_id")
    preissue_id = reservation.get("oracle_preissue_id")
    builder_run_id = reservation.get("managed_builder_run_id")
    experiment_id = reservation.get("managed_experiment_id")
    if (
        type(attempt_id) is not str
        or type(preissue_id) is not str
        or type(builder_run_id) is not str
        or type(experiment_id) is not str
        or reservation.get("status") != "reserved"
        or reservation.get("terminal") is not False
        or reservation.get("configuration_epoch")
        != state.configuration_epoch
        or reservation.get("source_manifest_sha256")
        != state.metadata.get("source_manifest_sha256")
    ):
        _fail("data_transcript_reservation_binding_changed")
    history = state.extra.get(DATA_TRANSCRIPT_STATE_KEY)
    if (
        type(history) is not dict
        or history.get(attempt_id) != reservation
    ):
        _fail("data_transcript_reservation_binding_changed")
    preissue_history = state.extra.get(
        MANAGED_ORACLE_PREISSUE_STATE_KEY
    )
    try:
        preissue = validate_public_record(
            preissue_history.get(preissue_id)
            if type(preissue_history) is dict
            else None
        )
    except ManagedOraclePreissueError:
        _fail("data_transcript_reservation_binding_changed")
    builder = next(
        (item for item in state.runs if item.id == builder_run_id),
        None,
    )
    experiment = next(
        (
            item
            for item in state.experiments
            if item.id == experiment_id
        ),
        None,
    )
    recipe = next(
        (
            item
            for item in state.artifacts
            if item.id == reservation.get("recipe_artifact_id")
        ),
        None,
    )
    if (
        preissue.get("status") != "consumed"
        or preissue.get("oracle_seal_sha256")
        != reservation.get("oracle_preissue_sha256")
        or preissue.get("consumed_by_builder_run_id")
        != builder_run_id
        or preissue.get("consumed_by_experiment_id")
        != experiment_id
        or builder is None
        or builder.role != "builder"
        or builder.origin is not RunOrigin.MANAGED_MODEL
        or builder.status is not RunStatus.COMPLETED
        or experiment is None
        or experiment.status is not ExperimentStatus.RUNNING
        or experiment.source_run_id != builder_run_id
        or recipe is None
        or recipe.source_run_id != builder_run_id
        or recipe.sha256 != reservation.get("recipe_sha256")
        or recipe.size != reservation.get("recipe_size_bytes")
    ):
        _fail("data_transcript_reservation_binding_changed")
    _read_artifact(
        engine.store.challenge_paths(identity).root,
        recipe,
        maximum_bytes=DATA_TRANSCRIPT_V1_MAX_DOCUMENT_BYTES,
    )
    run_ids = _reservation_run_ids(reservation)
    if any(item.id in run_ids for item in state.runs):
        _fail("data_transcript_reservation_run_state_invalid")
    return run_ids


def _terminalize_reserved_attempt(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    reservation: dict[str, object],
    failure: BaseException,
) -> ChallengeState:
    failure_code = _failure_code(failure)
    execution_error_type = type(failure).__name__[:128]
    attempt_id = str(reservation["attempt_id"])
    completed_at = utc_now()
    terminal_journal = {
        **copy.deepcopy(reservation),
        "completed_at": completed_at,
        "execution_error_type": execution_error_type,
        "failure_code": failure_code,
        "status": "failed",
        "terminal": True,
    }
    parent_result = _typed_gate_result(
        passed=False,
        reason_codes=("typed_gate_execution_error",),
        evaluation_sha256=None,
        evidence_artifact_ids=(),
        evidence_run_ids=(),
        execution_error_type=execution_error_type,
    )
    for _attempt in range(32):
        current = engine.store.load(identity, recover=False)
        _validate_reserved_attempt_state(
            engine,
            identity,
            current,
            reservation,
        )

        def terminalize(candidate: ChallengeState) -> None:
            _validate_reserved_attempt_state(
                engine,
                identity,
                candidate,
                reservation,
            )
            history = copy.deepcopy(
                candidate.extra[DATA_TRANSCRIPT_STATE_KEY]
            )
            history[attempt_id] = copy.deepcopy(terminal_journal)
            candidate.extra[DATA_TRANSCRIPT_STATE_KEY] = history
            _terminalize_parent_experiment(
                candidate,
                experiment_id=str(
                    reservation["managed_experiment_id"]
                ),
                builder_run_id=str(
                    reservation["managed_builder_run_id"]
                ),
                completed_at=completed_at,
                passed=False,
                result=parent_result,
            )

        try:
            return engine.store.update(
                identity,
                terminalize,
                expected_revision=current.revision,
            )
        except RevisionConflict:
            continue
    _fail("data_transcript_terminalization_revision_starved")
    raise AssertionError("unreachable")


def _published_recovery_run_ids(
    journal: dict[str, object],
) -> tuple[str, ...]:
    replays = journal.get("replays")
    if type(replays) is not list or len(replays) != 6:
        _fail("data_transcript_recovery_journal_invalid")
    run_ids: list[str] = []
    artifact_ids: set[str] = set()
    sidecar_artifact_ids: set[str] = set()
    expected_phases = (
        ("positive", 1),
        ("positive", 2),
        ("positive", 3),
        ("control", 1),
        ("control", 2),
        ("control", 3),
    )
    for replay, expected in zip(replays, expected_phases, strict=True):
        if (
            type(replay) is not dict
            or set(replay)
            != {
                "artifact_ids",
                "ordinal",
                "phase",
                "request_artifact",
                "result_artifact_id",
                "run_id",
                "validation_artifact_id",
            }
            or (replay.get("phase"), replay.get("ordinal")) != expected
            or type(replay.get("run_id")) is not str
            or not replay["run_id"]
            or type(replay.get("request_artifact")) is not dict
            or set(replay["request_artifact"])
            != {"artifact_id", "path", "sha256", "size_bytes"}
            or type(
                replay["request_artifact"].get("artifact_id")
            )
            is not str
            or not replay["request_artifact"]["artifact_id"]
            or type(replay["request_artifact"].get("path")) is not str
            or not replay["request_artifact"]["path"]
            or type(replay["request_artifact"].get("sha256"))
            is not str
            or re.fullmatch(
                r"[0-9a-f]{64}",
                replay["request_artifact"]["sha256"],
            )
            is None
            or type(replay["request_artifact"].get("size_bytes"))
            is not int
            or replay["request_artifact"]["size_bytes"] < 1
            or type(replay.get("result_artifact_id")) is not str
            or not replay["result_artifact_id"]
            or type(replay.get("validation_artifact_id")) is not str
            or not replay["validation_artifact_id"]
            or type(replay.get("artifact_ids")) is not list
            or len(replay["artifact_ids"]) != 6
            or any(
                type(item) is not str or not item
                for item in replay["artifact_ids"]
            )
        ):
            _fail("data_transcript_recovery_journal_invalid")
        run_ids.append(replay["run_id"])
        artifact_ids.update(replay["artifact_ids"])
        sidecar_artifact_ids.update(
            {
                replay["request_artifact"]["artifact_id"],
                replay["result_artifact_id"],
                replay["validation_artifact_id"],
            }
        )
    if (
        len(set(run_ids)) != 6
        or len(artifact_ids) != 36
        or len(sidecar_artifact_ids) != 18
        or artifact_ids & sidecar_artifact_ids
    ):
        _fail("data_transcript_recovery_journal_invalid")
    return tuple(run_ids)


def _validate_recoverable_published_state(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    state: ChallengeState,
    journal: dict[str, object],
) -> tuple[str, ...]:
    attempt_id = journal.get("attempt_id")
    preissue_id = journal.get("oracle_preissue_id")
    builder_run_id = journal.get("managed_builder_run_id")
    experiment_id = journal.get("managed_experiment_id")
    if (
        type(attempt_id) is not str
        or type(preissue_id) is not str
        or type(builder_run_id) is not str
        or type(experiment_id) is not str
        or journal.get("status") != "preissued"
        or journal.get("terminal") is not False
        or journal.get("configuration_epoch")
        != state.configuration_epoch
        or journal.get("source_manifest_sha256")
        != state.metadata.get("source_manifest_sha256")
        or journal.get("candidate_authorized") is not False
        or journal.get("automatic_submission_authorized") is not False
    ):
        _fail("data_transcript_recovery_binding_changed")
    history = state.extra.get(DATA_TRANSCRIPT_STATE_KEY)
    if type(history) is not dict or history.get(attempt_id) != journal:
        _fail("data_transcript_recovery_binding_changed")
    preissue_history = state.extra.get(
        MANAGED_ORACLE_PREISSUE_STATE_KEY
    )
    try:
        preissue = validate_public_record(
            preissue_history.get(preissue_id)
            if type(preissue_history) is dict
            else None
        )
    except ManagedOraclePreissueError:
        _fail("data_transcript_recovery_binding_changed")
    builder = next(
        (item for item in state.runs if item.id == builder_run_id),
        None,
    )
    experiment = next(
        (
            item
            for item in state.experiments
            if item.id == experiment_id
        ),
        None,
    )
    recipe = next(
        (
            item
            for item in state.artifacts
            if item.id == journal.get("recipe_artifact_id")
        ),
        None,
    )
    if (
        preissue.get("status") != "consumed"
        or preissue.get("oracle_seal_sha256")
        != journal.get("oracle_preissue_sha256")
        or preissue.get("consumed_by_builder_run_id")
        != builder_run_id
        or preissue.get("consumed_by_experiment_id")
        != experiment_id
        or builder is None
        or builder.role != "builder"
        or builder.origin is not RunOrigin.MANAGED_MODEL
        or builder.status is not RunStatus.COMPLETED
        or experiment is None
        or experiment.status is not ExperimentStatus.RUNNING
        or experiment.source_run_id != builder_run_id
        or recipe is None
        or recipe.source_run_id != builder_run_id
        or recipe.sha256 != journal.get("recipe_sha256")
        or recipe.size != journal.get("recipe_size_bytes")
    ):
        _fail("data_transcript_recovery_binding_changed")
    _read_artifact(
        engine.store.challenge_paths(identity).root,
        recipe,
        maximum_bytes=DATA_TRANSCRIPT_V1_MAX_DOCUMENT_BYTES,
    )
    run_ids = _published_recovery_run_ids(journal)
    run_index = {
        item.id: item for item in state.runs if item.id in run_ids
    }
    if set(run_index) != set(run_ids):
        _fail("data_transcript_recovery_run_state_invalid")
    replay_index = {
        str(item["run_id"]): item
        for item in journal["replays"]
        if type(item) is dict
    }
    artifact_index = {item.id: item for item in state.artifacts}
    paths = engine.store.challenge_paths(identity)
    base_revisions: set[int] = set()
    for run_id in run_ids:
        run = run_index[run_id]
        replay = replay_index[run_id]
        request_binding = replay["request_artifact"]
        request_artifact = artifact_index.get(
            request_binding["artifact_id"]
        )
        if (
            run.status is not RunStatus.CREATED
            or run.role != "data_transcript"
            or run.origin is not RunOrigin.MANAGED_TOOL
            or run.configuration_epoch != state.configuration_epoch
            or run.request_path != request_binding["path"]
            or run.extra.get("data_transcript", {}).get("attempt_id")
            != attempt_id
            or request_artifact is None
            or _artifact_binding(request_artifact)
            != request_binding
            or request_artifact.source_run_id != run_id
            or request_artifact.extra
            != {
                "attempt_id": attempt_id,
                "context_visibility": "engine_private",
                "kind": "data_transcript_request",
                "ordinal": replay["ordinal"],
                "phase": replay["phase"],
                "protocol": DATA_TRANSCRIPT_HOTPATH_PROTOCOL,
            }
        ):
            _fail("data_transcript_recovery_run_state_invalid")
        request_bytes = _read_artifact(
            paths.root,
            request_artifact,
            maximum_bytes=256 * 1024,
        )
        if (
            _sha256(request_bytes) != request_binding["sha256"]
            or len(request_bytes) != request_binding["size_bytes"]
        ):
            _fail("data_transcript_recovery_request_changed")
        base_revisions.add(run.base_revision)
    if len(base_revisions) != 1:
        _fail("data_transcript_recovery_run_state_invalid")
    return run_ids


def _terminalize_published_attempt(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    journal: dict[str, object],
    failure: BaseException,
) -> ChallengeState:
    """Persist exact failure sidecars, child runs, journal, and parent."""

    run_ids = _validate_recoverable_published_state(
        engine,
        identity,
        engine.store.load(identity, recover=False),
        journal,
    )
    issue_index: dict[str, _ReplayIssue] = {}
    for replay in journal["replays"]:
        sidecar_ids = (
            replay["request_artifact"]["artifact_id"],
            replay["result_artifact_id"],
            replay["validation_artifact_id"],
        )
        issue_index[str(replay["run_id"])] = _ReplayIssue(
            phase=str(replay["phase"]),
            ordinal=int(replay["ordinal"]),
            run_id=str(replay["run_id"]),
            artifact_ids=tuple(replay["artifact_ids"]),
            sidecar_artifact_ids=sidecar_ids,
        )
    failure_code = _failure_code(failure)
    execution_error_type = type(failure).__name__[:128]
    sidecars: dict[
        str, tuple[ArtifactReference, ArtifactReference]
    ] = {}
    for run_id in run_ids:
        issue = issue_index[run_id]
        (
            _result_path,
            _validation_path,
            _result_bytes,
            _validation_bytes,
            result_artifact,
            validation_artifact,
        ) = _write_exact_run_sidecars(
            engine,
            identity,
            issue,
            attempt_id=str(journal["attempt_id"]),
            result_document={
                "error": "data_transcript_execution_failed",
                "failure_code": failure_code,
                "protocol": DATA_TRANSCRIPT_HOTPATH_PROTOCOL,
                "terminal": True,
            },
            validation_document={
                "failure_code": failure_code,
                "ok": False,
                "protocol": DATA_TRANSCRIPT_HOTPATH_PROTOCOL,
                "terminal": True,
            },
        )
        sidecars[run_id] = (
            result_artifact,
            validation_artifact,
        )

    terminal_replays: list[dict[str, object]] = []
    evidence_artifact_ids = [
        str(replay["request_artifact"]["artifact_id"])
        for replay in journal["replays"]
    ]
    for replay in journal["replays"]:
        result_artifact, validation_artifact = sidecars[
            str(replay["run_id"])
        ]
        terminal_replays.append(
            {
                "artifact_ids": list(replay["artifact_ids"]),
                "ordinal": replay["ordinal"],
                "phase": replay["phase"],
                "request_artifact": copy.deepcopy(
                    replay["request_artifact"]
                ),
                "result_artifact": _artifact_binding(
                    result_artifact
                ),
                "run_id": replay["run_id"],
                "validation_artifact": _artifact_binding(
                    validation_artifact
                ),
            }
        )
    completed_at = utc_now()
    terminal_journal = {
        **{
            key: copy.deepcopy(value)
            for key, value in journal.items()
            if key != "replays"
        },
        "completed_at": completed_at,
        "execution_error_type": execution_error_type,
        "failure_code": failure_code,
        "replays": terminal_replays,
        "status": "failed",
        "terminal": True,
    }
    terminal_artifacts = tuple(
        artifact
        for run_id in run_ids
        for artifact in sidecars[run_id]
    )
    evidence_artifact_ids.extend(
        artifact.id for artifact in terminal_artifacts
    )
    parent_result = _typed_gate_result(
        passed=False,
        reason_codes=("typed_gate_execution_error",),
        evaluation_sha256=None,
        evidence_artifact_ids=tuple(evidence_artifact_ids),
        evidence_run_ids=run_ids,
        execution_error_type=execution_error_type,
    )

    for _attempt in range(32):
        current = engine.store.load(identity, recover=False)
        _validate_recoverable_published_state(
            engine,
            identity,
            current,
            journal,
        )

        def terminalize(candidate: ChallengeState) -> None:
            _validate_recoverable_published_state(
                engine,
                identity,
                candidate,
                journal,
            )
            existing_artifact_ids = {
                item.id for item in candidate.artifacts
            }
            if any(
                artifact.id in existing_artifact_ids
                for artifact in terminal_artifacts
            ):
                _fail("data_transcript_sidecar_artifact_reused")
            candidate.artifacts.extend(
                copy.deepcopy(terminal_artifacts)
            )
            run_index = {item.id: item for item in candidate.runs}
            for run_id in run_ids:
                run = run_index[run_id]
                result_artifact, validation_artifact = sidecars[run_id]
                run.status = RunStatus.FAILED
                run.result_path = result_artifact.path
                run.validation_path = validation_artifact.path
                run.extra["data_transcript"].update(
                    {
                        "failure_code": failure_code,
                        "terminal": True,
                    }
                )
            next_history = copy.deepcopy(
                candidate.extra[DATA_TRANSCRIPT_STATE_KEY]
            )
            next_history[str(journal["attempt_id"])] = copy.deepcopy(
                terminal_journal
            )
            candidate.extra[DATA_TRANSCRIPT_STATE_KEY] = next_history
            _terminalize_parent_experiment(
                candidate,
                experiment_id=str(journal["managed_experiment_id"]),
                builder_run_id=str(
                    journal["managed_builder_run_id"]
                ),
                completed_at=completed_at,
                passed=False,
                result=parent_result,
            )

        try:
            return engine.store.update(
                identity,
                terminalize,
                expected_revision=current.revision,
            )
        except RevisionConflict:
            continue
    _fail("data_transcript_terminalization_revision_starved")
    raise AssertionError("unreachable")


def recover_data_transcript_attempts(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
) -> ChallengeState:
    """Fail closed crash-left reserved/preissued transcript attempts."""

    state = engine.store.load(identity, recover=False)
    history = state.extra.get(DATA_TRANSCRIPT_STATE_KEY)
    if type(history) is not dict:
        return state
    pending = [
        copy.deepcopy(value)
        for value in history.values()
        if type(value) is dict
        and value.get("protocol") == DATA_TRANSCRIPT_HOTPATH_PROTOCOL
        and value.get("terminal") is False
        and value.get("status") in {"reserved", "preissued"}
    ]
    for journal in pending:
        if journal["status"] == "reserved":
            run_ids = _validate_reserved_attempt_state(
                engine,
                identity,
                state,
                journal,
            )
            _cleanup_uncommitted_run_directories(
                engine,
                identity,
                run_ids,
            )
            state = _terminalize_reserved_attempt(
                engine,
                identity,
                journal,
                DataTranscriptHotPathError(
                    "data_transcript_orphan_recovered"
                ),
            )
            continue

        state = _terminalize_published_attempt(
            engine,
            identity,
            journal,
            DataTranscriptHotPathError(
                "data_transcript_orphan_recovered"
            ),
        )
    return state


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
        raise DataTranscriptHotPathError(
            "data_transcript_sandbox_artifact_changed"
        ) from error


def _read_unbound_stable_regular(
    root: Path,
    locator: str,
    *,
    maximum_bytes: int,
) -> bytes:
    """Establish a bounded sidecar binding through one stable descriptor."""

    from ctf_os.sandbox.files import normalize_locator

    try:
        normalized = normalize_locator(locator)
    except SafeFileError as error:
        raise DataTranscriptHotPathError(
            "data_transcript_sidecar_path_invalid"
        ) from error
    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    file_flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_fd: int | None = None
    file_fd: int | None = None
    try:
        directory_fd = os.open(root, directory_flags)
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
                "sidecar is not a bounded regular file"
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
        if (
            len(payload) != before.st_size
            or len(payload) > maximum_bytes
            or any(
                getattr(before, name) != getattr(after, name)
                for name in (
                    "st_dev",
                    "st_ino",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            )
        ):
            raise SafeFileError(
                "sidecar changed during bounded read"
            )
        return bytes(payload)
    except (OSError, SafeFileError) as error:
        raise DataTranscriptHotPathError(
            "data_transcript_sidecar_binding_invalid"
        ) from error
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def _artifact_from_bytes(
    *,
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
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
    engine._enforce_storage_admission(
        identity,
        requested_bytes=len(payload),
    )
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
                "evaluation",
                "producer_stdout",
                "reset_proof",
                "transcript",
            }
            else "application/octet-stream"
        ),
        size=len(payload),
        extra={
            "attempt_id": attempt_id,
            "context_visibility": "engine_private",
            "kind": f"data_transcript_{kind}",
            "ordinal": ordinal,
            "phase": phase,
            "protocol": DATA_TRANSCRIPT_HOTPATH_PROTOCOL,
        },
    )


def _complete_transport(result: SandboxResult) -> bool:
    return (
        type(result) is SandboxResult
        and result.timed_out is False
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
        and type(result.stdout_stored_bytes) is int
        and type(result.stderr_stored_bytes) is int
        and result.stdout_stored_bytes == result.stdout_bytes
        and result.stderr_stored_bytes == result.stderr_bytes
    )


def _probe_capability(
    engine: ChallengeEngine,
    image_digest: str,
) -> None:
    report = (
        engine._capability_probe(
            image_digest,
            timeout_seconds=30.0,
        )
        if engine._capability_probe_accepts_timeout
        else engine._capability_probe(image_digest)
    )
    expected = REQUIRED_MANAGED_ATTESTATIONS[
        DATA_TRANSCRIPT_CAPABILITY
    ]
    if (
        type(report) is not dict
        or report.get("ok") is not True
        or report.get("image_digest") != image_digest
        or DATA_TRANSCRIPT_CAPABILITY
        not in report.get("available", ())
        or type(report.get("attestations")) is not dict
        or report["attestations"].get(
            DATA_TRANSCRIPT_CAPABILITY
        )
        != expected
        or report.get("attestation_errors") not in ({}, None)
    ):
        _fail("data_transcript_capability_unavailable")


def _producer_command(
    *,
    category: str,
    phase: str,
    ordinal: int,
    preissue_id: str,
    preissue_sha256: str,
    recipe_sha256: str,
    recipe_size_bytes: int,
    reset_commitment_sha256: str,
    peer_sha256: str,
    peer_size_bytes: int,
    peer_data_sha256: str,
    peer_data_size_bytes: int,
    image_digest: str,
    configuration_epoch: int,
    timeout_milliseconds: int,
) -> tuple[CommandSpec, tuple[ProofInput, ...], tuple[ProofOutput, ...]]:
    """Construct the only command and file bindings accepted by the hot path."""

    output_root = (
        f".ctf/data-transcript-v1/{preissue_id}/"
        f"{recipe_sha256}/{phase}-{ordinal}"
    )
    proof_outputs = tuple(
        ProofOutput(
            source_locator=f"{output_root}/{name}",
            name=name,
            maximum_bytes=maximum,
        )
        for name, maximum, _kind in _OUTPUT_SPECS
    )
    proof_inputs = (
        ProofInput(
            source_locator="inputs/peer",
            destination_locator="bound/peer",
            sha256=peer_sha256,
            size_bytes=peer_size_bytes,
        ),
        ProofInput(
            source_locator="inputs/peer-data.bin",
            destination_locator="bound/peer-data.bin",
            sha256=peer_data_sha256,
            size_bytes=peer_data_size_bytes,
        ),
        ProofInput(
            source_locator="inputs/recipe.json",
            destination_locator="bound/recipe.json",
            sha256=recipe_sha256,
            size_bytes=recipe_size_bytes,
        ),
    )
    command_timeout = max(
        1,
        min(135, math.ceil(timeout_milliseconds / 1000) + 15),
    )
    command = CommandSpec.create(
        (
            "/usr/bin/python3",
            DATA_TRANSCRIPT_PRODUCER_PATH,
            "--peer",
            "/work/bound/peer",
            "--peer-data",
            "/work/bound/peer-data.bin",
            "--recipe",
            "/work/bound/recipe.json",
            "--work-root",
            "/work",
            "--category",
            category,
            "--phase",
            phase,
            "--ordinal",
            str(ordinal),
            "--preissue-id",
            preissue_id,
            "--preissue-sha256",
            preissue_sha256,
            "--producer-sha256",
            DATA_TRANSCRIPT_PRODUCER_SHA256,
            "--recipe-sha256",
            recipe_sha256,
            "--recipe-size-bytes",
            str(recipe_size_bytes),
            "--peer-sha256",
            peer_sha256,
            "--peer-size-bytes",
            str(peer_size_bytes),
            "--peer-data-sha256",
            peer_data_sha256,
            "--peer-data-size-bytes",
            str(peer_data_size_bytes),
            "--reset-commitment-sha256",
            reset_commitment_sha256,
            "--image-digest",
            image_digest,
            "--configuration-epoch",
            str(configuration_epoch),
        ),
        timeout_seconds=command_timeout,
        summary_bytes=DATA_TRANSCRIPT_MAX_RESULT_BYTES,
        resource_request=DATA_TRANSCRIPT_RESOURCE,
        network_target=None,
    )
    return command, proof_inputs, proof_outputs


def _expected_kind(category: str) -> str:
    if category == "crypto":
        return MANAGED_ORACLE_PREISSUE_CRYPTO_TRANSCRIPT
    if category == "misc":
        return MANAGED_ORACLE_PREISSUE_MISC_TRANSCRIPT
    _fail("data_transcript_category_invalid")
    raise AssertionError("unreachable")


def prove_data_transcript(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    recipe_locator: str,
    recipe_artifact_id: str,
    recipe_sha256: str,
    recipe_size_bytes: int,
    oracle_preissue_id: str,
    _session_owned: bool = False,
    _managed_builder_run_id: str | None = None,
    _managed_experiment_id: str | None = None,
) -> tuple[ChallengeState, DataTranscriptEvaluation]:
    """Consume one managed transcript preissue and execute its exact 3+3 gate."""

    from ctf_os.engine.challenge import EngineError, SessionAlreadyRunning

    if (
        type(recipe_locator) is not str
        or not recipe_locator
        or type(recipe_artifact_id) is not str
        or not recipe_artifact_id
        or type(recipe_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", recipe_sha256) is None
        or type(recipe_size_bytes) is not int
        or not 1
        <= recipe_size_bytes
        <= DATA_TRANSCRIPT_V1_MAX_DOCUMENT_BYTES
        or type(oracle_preissue_id) is not str
        or not oracle_preissue_id
        or type(_managed_builder_run_id) is not str
        or not _managed_builder_run_id
        or type(_managed_experiment_id) is not str
        or not _managed_experiment_id
    ):
        raise EngineError(
            "data transcript execution requires one managed Builder recipe "
            "and one operator preissue"
        )

    paths = engine.store.challenge_paths(identity)
    if not _session_owned:
        try:
            session_lock = ChallengeLock(
                paths.runtime / "session.lock",
                timeout=0,
            ).acquire()
        except LockTimeout as error:
            raise SessionAlreadyRunning(
                f"another session already owns {identity.key}"
            ) from error
        try:
            engine._recover_session_boundary(identity)
            return prove_data_transcript(
                engine,
                identity,
                recipe_locator=recipe_locator,
                recipe_artifact_id=recipe_artifact_id,
                recipe_sha256=recipe_sha256,
                recipe_size_bytes=recipe_size_bytes,
                oracle_preissue_id=oracle_preissue_id,
                _session_owned=True,
                _managed_builder_run_id=_managed_builder_run_id,
                _managed_experiment_id=_managed_experiment_id,
            )
        finally:
            session_lock.release()

    engine._enforce_storage_admission(identity)
    state = engine.refresh_ingest(identity)
    try:
        category = get_adapter(state.category).name
    except (KeyError, ValueError) as error:
        raise EngineError(
            "data transcript challenge category is invalid"
        ) from error
    if (
        state.schema_version < STATE_SCHEMA_VERSION
        or category not in {"crypto", "misc"}
        or state.status in _INACTIVE_STATUSES
        or state.primary_target_id is not None
    ):
        raise EngineError(
            "data transcript execution requires one active local "
            "Crypto or Misc challenge"
        )
    image_digest = engine.config.runtime.image_digest
    source_manifest_sha256 = state.metadata.get(
        "source_manifest_sha256"
    )
    if (
        type(image_digest) is not str
        or _IMAGE_DIGEST.fullmatch(image_digest) is None
        or type(source_manifest_sha256) is not str
        or re.fullmatch(
            r"[0-9a-f]{64}",
            source_manifest_sha256,
        )
        is None
    ):
        raise EngineError(
            "data transcript execution requires pinned image and source"
        )
    expected_kind = _expected_kind(category)
    before_status = state.status
    before_candidates = tuple(item.id for item in state.candidates)
    before_submissions = tuple(item.id for item in state.submissions)
    configuration_epoch = state.configuration_epoch

    recipe_artifact, recipe_bytes = _resolve_pinned_recipe(
        state,
        challenge_root=paths.root,
        workspace_root=paths.artifacts / "workspace",
        recipe_locator=recipe_locator,
        recipe_artifact_id=recipe_artifact_id,
        recipe_sha256=recipe_sha256,
        recipe_size_bytes=recipe_size_bytes,
        builder_run_id=_managed_builder_run_id,
    )
    try:
        recipe = parse_data_transcript_v1_recipe(recipe_bytes)
    except DataTranscriptContractError as error:
        raise EngineError(
            f"invalid data transcript recipe: {error.code}"
        ) from error
    if (
        recipe.canonical_bytes != recipe_bytes
        or recipe.category != category
        or recipe.preissue_id != oracle_preissue_id
    ):
        raise EngineError(
            "data transcript recipe is not canonical or preissue-bound"
        )

    history = state.extra.get(MANAGED_ORACLE_PREISSUE_STATE_KEY)
    try:
        public_preissue = validate_public_record(
            history.get(oracle_preissue_id)
            if type(history) is dict
            else None
        )
    except ManagedOraclePreissueError as error:
        raise EngineError(
            "data transcript operator preissue is invalid"
        ) from error
    if (
        public_preissue.get("preissue_id") != oracle_preissue_id
        or public_preissue.get("kind") != expected_kind
        or public_preissue.get("status") != "unused"
        or public_preissue.get("configuration_epoch")
        != configuration_epoch
        or public_preissue.get("source_manifest_sha256")
        != source_manifest_sha256
        or public_preissue.get("image_digest") != image_digest
        or public_preissue.get("reset_commitment_sha256")
        != recipe.reset_commitment_sha256
    ):
        raise EngineError(
            "data transcript operator preissue is stale or rebound"
        )

    attempt_id = _new_id("data-transcript")
    evaluation_artifact_id = _new_id(
        "A-data-transcript-evaluation"
    )
    phases = (
        ("positive", 1),
        ("positive", 2),
        ("positive", 3),
        ("control", 1),
        ("control", 2),
        ("control", 3),
    )
    issues = tuple(
        _ReplayIssue(
            phase=phase,
            ordinal=ordinal,
            run_id=_new_id("data-transcript-run"),
            artifact_ids=tuple(
                _new_id(f"A-data-transcript-{kind}")
                for _name, _maximum, kind in (
                    (
                        "producer.stdout",
                        DATA_TRANSCRIPT_MAX_RESULT_BYTES,
                        "producer_stdout",
                    ),
                    (
                        "producer.stderr",
                        DATA_TRANSCRIPT_MAX_RESULT_BYTES,
                        "producer_stderr",
                    ),
                    *_OUTPUT_SPECS,
                )
            ),
            sidecar_artifact_ids=(
                _new_id("A-data-transcript-request"),
                _new_id("A-data-transcript-result"),
                _new_id("A-data-transcript-validation"),
            ),
        )
        for phase, ordinal in phases
    )
    if (
        len({item.run_id for item in issues}) != 6
        or len(
            {
                artifact_id
                for item in issues
                for artifact_id in item.artifact_ids
            }
        )
        != 36
        or len(
            {
                artifact_id
                for item in issues
                for artifact_id in item.sidecar_artifact_ids
            }
        )
        != 18
        or {
            artifact_id
            for item in issues
            for artifact_id in item.artifact_ids
        }
        & {
            artifact_id
            for item in issues
            for artifact_id in item.sidecar_artifact_ids
        }
    ):
        _fail("data_transcript_identity_collision")
    transcript_history = state.extra.get(DATA_TRANSCRIPT_STATE_KEY, {})
    if (
        type(transcript_history) is not dict
        or len(transcript_history) >= DATA_TRANSCRIPT_MAX_HISTORY
        or attempt_id in transcript_history
    ):
        _fail("data_transcript_history_invalid_or_full")
    occupied_run_ids = {item.id for item in state.runs}
    occupied_artifact_ids = {item.id for item in state.artifacts}
    for existing_journal in transcript_history.values():
        if type(existing_journal) is not dict:
            continue
        existing_replays = existing_journal.get("replays")
        if type(existing_replays) is not list:
            continue
        for existing_replay in existing_replays:
            if type(existing_replay) is not dict:
                continue
            existing_run_id = existing_replay.get("run_id")
            if type(existing_run_id) is str:
                occupied_run_ids.add(existing_run_id)
            existing_artifacts = existing_replay.get("artifact_ids")
            if type(existing_artifacts) is list:
                occupied_artifact_ids.update(
                    item
                    for item in existing_artifacts
                    if type(item) is str
                )
            planned_sidecars = existing_replay.get(
                "sidecar_artifact_ids"
            )
            if type(planned_sidecars) is dict:
                occupied_artifact_ids.update(
                    item
                    for item in planned_sidecars.values()
                    if type(item) is str
                )
            for key in (
                "request_artifact",
                "result_artifact",
                "validation_artifact",
            ):
                binding = existing_replay.get(key)
                if (
                    type(binding) is dict
                    and type(binding.get("artifact_id")) is str
                ):
                    occupied_artifact_ids.add(
                        binding["artifact_id"]
                    )
            for key in (
                "result_artifact_id",
                "validation_artifact_id",
            ):
                artifact_id = existing_replay.get(key)
                if type(artifact_id) is str:
                    occupied_artifact_ids.add(artifact_id)
        evaluation_id = existing_journal.get(
            "evaluation_artifact_id"
        )
        if type(evaluation_id) is str:
            occupied_artifact_ids.add(evaluation_id)
    generated_run_ids = {item.run_id for item in issues}
    generated_artifact_ids = {
        evaluation_artifact_id,
        *(
            artifact_id
            for item in issues
            for artifact_id in (
                *item.artifact_ids,
                *item.sidecar_artifact_ids,
            )
        ),
    }
    if (
        generated_run_ids & occupied_run_ids
        or generated_artifact_ids & occupied_artifact_ids
    ):
        _fail("data_transcript_identity_collision")
    reservation = {
        "attempt_id": attempt_id,
        "automatic_submission_authorized": False,
        "candidate_authorized": False,
        "configuration_epoch": configuration_epoch,
        "contract_fingerprint": (
            DATA_TRANSCRIPT_V1_CONTRACT_FINGERPRINT
        ),
        "image_digest": image_digest,
        "managed_builder_run_id": _managed_builder_run_id,
        "managed_experiment_id": _managed_experiment_id,
        "oracle_preissue_id": oracle_preissue_id,
        "oracle_preissue_sha256": public_preissue[
            "oracle_seal_sha256"
        ],
        "protocol": DATA_TRANSCRIPT_HOTPATH_PROTOCOL,
        "recipe_artifact_id": recipe_artifact_id,
        "recipe_sha256": recipe_sha256,
        "recipe_size_bytes": recipe_size_bytes,
        "reset_commitment_sha256": recipe.reset_commitment_sha256,
        "replays": [
            {
                "artifact_ids": list(issue.artifact_ids),
                "ordinal": issue.ordinal,
                "phase": issue.phase,
                "run_id": issue.run_id,
                "sidecar_artifact_ids": {
                    "request": issue.sidecar_artifact_ids[0],
                    "result": issue.sidecar_artifact_ids[1],
                    "validation": issue.sidecar_artifact_ids[2],
                },
            }
            for issue in issues
        ],
        "schema_version": DATA_TRANSCRIPT_HOTPATH_SCHEMA_VERSION,
        "source_manifest_sha256": source_manifest_sha256,
        "status": "reserved",
        "terminal": False,
    }

    # This is the only authority transition.  It occurs before any sandbox
    # call, atomically reserves recovery identity, and consumes exactly once.
    resolution = engine._consume_managed_oracle_preissue(
        identity,
        preissue_id=oracle_preissue_id,
        expected_kind=expected_kind,
        builder_run_id=_managed_builder_run_id,
        experiment_id=_managed_experiment_id,
        transcript_attempt_id=attempt_id,
        transcript_reservation=reservation,
    )
    try:
        consumed_state = engine.store.load(identity, recover=False)
        reserved_history = consumed_state.extra.get(
            DATA_TRANSCRIPT_STATE_KEY
        )
        if (
            type(reserved_history) is not dict
            or reserved_history.get(attempt_id) != reservation
        ):
            _fail("data_transcript_reservation_binding_changed")
        manifest = resolution.manifest
        manifest_inputs = tuple(manifest.inputs)
        if (
            manifest.preissue_id != oracle_preissue_id
            or manifest.kind != expected_kind
            or manifest.configuration_epoch != configuration_epoch
            or manifest.source_manifest_sha256 != source_manifest_sha256
            or manifest.image_digest != image_digest
            or tuple(item.purpose for item in manifest_inputs)
            != ("transcript_peer", "transcript_peer_data")
            or len(resolution.bindings) != 2
            or tuple(
                binding.purpose
                for _artifact, binding in resolution.bindings
            )
            != ("transcript_peer", "transcript_peer_data")
        ):
            _fail("data_transcript_private_preissue_binding_invalid")
        peer_artifact, peer_binding = resolution.bindings[0]
        peer_data_artifact, peer_data_binding = resolution.bindings[1]
        if (
            peer_artifact.id != manifest_inputs[0].artifact_id
            or peer_artifact.sha256 != manifest_inputs[0].sha256
            or peer_artifact.size != manifest_inputs[0].size_bytes
            or peer_binding.artifact_id != peer_artifact.id
            or peer_binding.destination != "oracle/peer"
            or peer_binding.purpose != "transcript_peer"
            or peer_binding.sha256 != peer_artifact.sha256
            or peer_binding.size != peer_artifact.size
            or peer_binding.source_run_id is not None
            or peer_data_artifact.id != manifest_inputs[1].artifact_id
            or peer_data_artifact.sha256 != manifest_inputs[1].sha256
            or peer_data_artifact.size
            != manifest_inputs[1].size_bytes
            or peer_data_binding.artifact_id != peer_data_artifact.id
            or peer_data_binding.destination != "oracle/peer-data.bin"
            or peer_data_binding.purpose != "transcript_peer_data"
            or peer_data_binding.sha256 != peer_data_artifact.sha256
            or peer_data_binding.size != peer_data_artifact.size
            or peer_data_binding.source_run_id is not None
            or peer_artifact.source_run_id is not None
            or peer_data_artifact.source_run_id is not None
            or peer_artifact.extra.get("kind")
            != "managed_oracle_preissue_input"
            or peer_data_artifact.extra.get("kind")
            != "managed_oracle_preissue_input"
            or peer_artifact.extra.get("protocol")
            != MANAGED_ORACLE_PREISSUE_PROTOCOL
            or peer_data_artifact.extra.get("protocol")
            != MANAGED_ORACLE_PREISSUE_PROTOCOL
            or peer_artifact.extra.get("preissue_id")
            != oracle_preissue_id
            or peer_data_artifact.extra.get("preissue_id")
            != oracle_preissue_id
            or peer_artifact.extra.get("purpose")
            != "transcript_peer"
            or peer_data_artifact.extra.get("purpose")
            != "transcript_peer_data"
            or peer_artifact.extra.get("context_visibility")
            != "engine_private"
            or peer_data_artifact.extra.get("context_visibility")
            != "engine_private"
        ):
            _fail("data_transcript_private_input_binding_invalid")
        reset_commitment = data_transcript_v1_reset_commitment_sha256(
            category=category,
            peer_sha256=peer_artifact.sha256,
            peer_size_bytes=int(peer_artifact.size or 0),
            peer_data_sha256=peer_data_artifact.sha256,
            peer_data_size_bytes=int(peer_data_artifact.size or 0),
        )
        if (
            manifest.metadata
            != {"reset_commitment_sha256": reset_commitment}
            or recipe.reset_commitment_sha256 != reset_commitment
            or public_preissue["oracle_seal_sha256"] != manifest.sha256
        ):
            _fail("data_transcript_reset_commitment_mismatch")
        consumed_history = consumed_state.extra.get(
            MANAGED_ORACLE_PREISSUE_STATE_KEY
        )
        try:
            consumed_record = validate_public_record(
                consumed_history.get(oracle_preissue_id)
                if type(consumed_history) is dict
                else None
            )
        except ManagedOraclePreissueError as error:
            raise DataTranscriptHotPathError(
                "data_transcript_consumption_record_invalid"
            ) from error
        if (
            consumed_record.get("status") != "consumed"
            or consumed_record.get("consumed_by_builder_run_id")
            != _managed_builder_run_id
            or consumed_record.get("consumed_by_experiment_id")
            != _managed_experiment_id
        ):
            _fail("data_transcript_consumption_record_invalid")

        _probe_capability(engine, image_digest)
        current_recipe_artifact, current_recipe_bytes = (
            _resolve_pinned_recipe(
                consumed_state,
                challenge_root=paths.root,
                workspace_root=paths.artifacts / "workspace",
                recipe_locator=recipe_locator,
                recipe_artifact_id=recipe_artifact_id,
                recipe_sha256=recipe_sha256,
                recipe_size_bytes=recipe_size_bytes,
                builder_run_id=_managed_builder_run_id,
            )
        )
        if (
            current_recipe_artifact != recipe_artifact
            or current_recipe_bytes != recipe_bytes
        ):
            _fail("data_transcript_recipe_artifact_binding_invalid")
    except BaseException as failure:
        try:
            _terminalize_reserved_attempt(
                engine,
                identity,
                reservation,
                failure,
            )
        except BaseException as terminal_error:
            failure.add_note(
                "data transcript reservation terminalization failed: "
                f"{type(terminal_error).__name__}"
            )
        raise

    private_workspace: tempfile.TemporaryDirectory[str] | None = None
    captures: list[_ReplayCapture] = []
    pending_artifacts: list[ArtifactReference] = []
    lease = None
    preissued_revision: int | None = None
    journal_preissue: dict[str, object] | None = None
    evaluation: DataTranscriptEvaluation | None = None
    uncommitted_run_ids: list[str] = []
    try:
        private_workspace, proof_root = (
            engine._open_managed_oracle_proof_workspace(consumed_state)
        )
        input_root = proof_root / "inputs"
        copy_bounded_regular(
            paths.root,
            peer_artifact.path,
            input_root / "peer",
            maximum_bytes=max(1, int(peer_artifact.size or 0)),
            expected_sha256=peer_artifact.sha256,
            expected_size=int(peer_artifact.size or 0),
            source_size_admission=lambda size: (
                engine._enforce_storage_admission(
                    identity,
                    requested_bytes=size,
                )
            ),
            mode=0o500,
        )
        copy_bounded_regular(
            paths.root,
            peer_data_artifact.path,
            input_root / "peer-data.bin",
            maximum_bytes=max(1, int(peer_data_artifact.size or 0)),
            expected_sha256=peer_data_artifact.sha256,
            expected_size=int(peer_data_artifact.size or 0),
            source_size_admission=lambda size: (
                engine._enforce_storage_admission(
                    identity,
                    requested_bytes=size,
                )
            ),
            mode=0o400,
        )
        engine._enforce_storage_admission(
            identity,
            requested_bytes=len(recipe.canonical_bytes),
        )
        atomic_write_bytes(
            input_root / "recipe.json",
            recipe.canonical_bytes,
            mode=0o400,
        )
        empty_challenge = ensure_private_directory(
            proof_root / "empty-challenge"
        )
        client = engine.sandbox(
            consumed_state,
            workspace_override=proof_root,
            challenge_dir_override=empty_challenge,
            network_policy_override=NetworkPolicy.deny_all(),
        )
        canonical_scope = client.scope_fingerprint
        if (
            type(canonical_scope) is not str
            or re.fullmatch(r"[0-9a-f]{64}", canonical_scope) is None
        ):
            _fail("data_transcript_scope_binding_invalid")

        timeout_milliseconds = int(
            recipe.document["timeout_milliseconds"]
        )
        commands = tuple(
            _producer_command(
                category=category,
                phase=issue.phase,
                ordinal=issue.ordinal,
                preissue_id=oracle_preissue_id,
                preissue_sha256=manifest.sha256,
                recipe_sha256=recipe.sha256,
                recipe_size_bytes=len(recipe.canonical_bytes),
                reset_commitment_sha256=reset_commitment,
                peer_sha256=peer_artifact.sha256,
                peer_size_bytes=int(peer_artifact.size or 0),
                peer_data_sha256=peer_data_artifact.sha256,
                peer_data_size_bytes=int(peer_data_artifact.size or 0),
                image_digest=image_digest,
                configuration_epoch=configuration_epoch,
                timeout_milliseconds=timeout_milliseconds,
            )
            for issue in issues
        )
        run_request_paths: dict[str, str] = {}
        run_request_bytes: dict[str, bytes] = {}
        run_request_artifacts: dict[str, ArtifactReference] = {}
        base_revision = consumed_state.revision
        for issue, (command, proof_inputs, proof_outputs) in zip(
            issues,
            commands,
            strict=True,
        ):
            uncommitted_run_ids.append(issue.run_id)
            run_paths = engine.store.create_run(
                identity,
                issue.run_id,
                request={
                    "attempt_id": attempt_id,
                    "automatic_submission_authorized": False,
                    "candidate_authorized": False,
                    "command": {
                        "argv": list(command.argv),
                        "environment": dict(command.environment),
                        "network_target": None,
                        "resource_request": {
                            "cpu": command.resource_request.cpu,
                            "gpu": command.resource_request.gpu,
                            "kvm": command.resource_request.kvm,
                            "memory_mib": (
                                command.resource_request.memory_mib
                            ),
                            "network": command.resource_request.network,
                        },
                        "summary_bytes": command.summary_bytes,
                        "timeout_seconds": command.timeout_seconds,
                    },
                    "oracle_preissue_id": oracle_preissue_id,
                    "oracle_preissue_sha256": manifest.sha256,
                    "proof_inputs": [
                        item.as_dict() for item in proof_inputs
                    ],
                    "proof_outputs": [
                        item.as_dict() for item in proof_outputs
                    ],
                    "protocol": DATA_TRANSCRIPT_HOTPATH_PROTOCOL,
                    "recipe_artifact_id": recipe_artifact.id,
                    "recipe_sha256": recipe.sha256,
                    "recipe_size_bytes": len(
                        recipe.canonical_bytes
                    ),
                    "replay": {
                        "ordinal": issue.ordinal,
                        "phase": issue.phase,
                    },
                    "schema_version": (
                        DATA_TRANSCRIPT_HOTPATH_SCHEMA_VERSION
                    ),
                    "sidecar_artifact_ids": {
                        "request": issue.sidecar_artifact_ids[0],
                        "result": issue.sidecar_artifact_ids[1],
                        "validation": issue.sidecar_artifact_ids[2],
                    },
                    "transport": {
                        "clean_workspace": True,
                        "declared_output_count": 4,
                        "network": "none",
                        "one_shot": True,
                        "sandbox_method": "run_clean_proof",
                    },
                },
                base_revision=base_revision,
            )
            request_bytes = _read_unbound_stable_regular(
                paths.root,
                run_paths.request.relative_to(paths.root).as_posix(),
                maximum_bytes=256 * 1024,
            )
            run_request_bytes[issue.run_id] = request_bytes
            run_request_paths[issue.run_id] = (
                run_paths.request.relative_to(paths.root).as_posix()
            )
            run_request_artifacts[issue.run_id] = _sidecar_artifact(
                artifact_id=issue.sidecar_artifact_ids[0],
                path=run_request_paths[issue.run_id],
                payload=request_bytes,
                run_id=issue.run_id,
                kind="request",
                attempt_id=attempt_id,
                phase=issue.phase,
                ordinal=issue.ordinal,
            )

        journal_preissue = {
            **copy.deepcopy(reservation),
            "capability": copy.deepcopy(
                REQUIRED_MANAGED_ATTESTATIONS[
                    DATA_TRANSCRIPT_CAPABILITY
                ]
            ),
            "replays": [
                {
                    "artifact_ids": list(issue.artifact_ids),
                    "ordinal": issue.ordinal,
                    "phase": issue.phase,
                    "request_artifact": _artifact_binding(
                        run_request_artifacts[issue.run_id]
                    ),
                    "result_artifact_id": (
                        issue.sidecar_artifact_ids[1]
                    ),
                    "run_id": issue.run_id,
                    "validation_artifact_id": (
                        issue.sidecar_artifact_ids[2]
                    ),
                }
                for issue in issues
            ],
            "status": "preissued",
        }

        def verify_base(*, expect_revision: int) -> ChallengeState:
            current = engine.store.load(identity, recover=False)
            current_experiment = next(
                (
                    item
                    for item in current.experiments
                    if item.id == _managed_experiment_id
                ),
                None,
            )
            if (
                current.revision != expect_revision
                or current.schema_version < STATE_SCHEMA_VERSION
                or get_adapter(current.category).name != category
                or current.configuration_epoch != configuration_epoch
                or current.metadata.get("source_manifest_sha256")
                != source_manifest_sha256
                or current.status is not before_status
                or current.primary_target_id is not None
                or tuple(item.id for item in current.candidates)
                != before_candidates
                or tuple(item.id for item in current.submissions)
                != before_submissions
                or engine.config.runtime.image_digest != image_digest
                or current_experiment is None
                or current_experiment.status
                is not ExperimentStatus.RUNNING
            ):
                _fail("data_transcript_runtime_binding_changed")
            observed_inventory = inventory_challenge(
                engine.challenge_input(identity)
            )
            if (
                observed_inventory.manifest_sha256
                != source_manifest_sha256
            ):
                _fail("data_transcript_source_changed")
            current_recipe = next(
                (
                    item
                    for item in current.artifacts
                    if item.id == recipe_artifact.id
                ),
                None,
            )
            current_peer = next(
                (
                    item
                    for item in current.artifacts
                    if item.id == peer_artifact.id
                ),
                None,
            )
            current_peer_data = next(
                (
                    item
                    for item in current.artifacts
                    if item.id == peer_data_artifact.id
                ),
                None,
            )
            try:
                pinned_recipe, pinned_recipe_bytes = (
                    _resolve_pinned_recipe(
                        current,
                        challenge_root=paths.root,
                        workspace_root=(
                            paths.artifacts / "workspace"
                        ),
                        recipe_locator=recipe_locator,
                        recipe_artifact_id=recipe_artifact_id,
                        recipe_sha256=recipe_sha256,
                        recipe_size_bytes=recipe_size_bytes,
                        builder_run_id=_managed_builder_run_id,
                    )
                )
            except DataTranscriptHotPathError:
                _fail("data_transcript_bound_input_changed")
            if (
                current_recipe != pinned_recipe
                or pinned_recipe != recipe_artifact
                or pinned_recipe_bytes != recipe.canonical_bytes
                or current_peer != peer_artifact
                or current_peer_data != peer_data_artifact
                or _read_artifact(
                    paths.root,
                    current_peer,
                    maximum_bytes=max(
                        1, int(peer_artifact.size or 0)
                    ),
                )
                != _read_artifact(
                    proof_root,
                    ArtifactReference(
                        id="staged-peer",
                        path="inputs/peer",
                        sha256=peer_artifact.sha256,
                        size=peer_artifact.size,
                    ),
                    maximum_bytes=max(
                        1, int(peer_artifact.size or 0)
                    ),
                )
                or _read_artifact(
                    paths.root,
                    current_peer_data,
                    maximum_bytes=max(
                        1, int(peer_data_artifact.size or 0)
                    ),
                )
                != _read_artifact(
                    proof_root,
                    ArtifactReference(
                        id="staged-peer-data",
                        path="inputs/peer-data.bin",
                        sha256=peer_data_artifact.sha256,
                        size=peer_data_artifact.size,
                    ),
                    maximum_bytes=max(
                        1, int(peer_data_artifact.size or 0)
                    ),
                )
            ):
                _fail("data_transcript_bound_input_changed")
            consumed = current.extra.get(
                MANAGED_ORACLE_PREISSUE_STATE_KEY
            )
            try:
                record = validate_public_record(
                    consumed.get(oracle_preissue_id)
                    if type(consumed) is dict
                    else None
                )
            except ManagedOraclePreissueError:
                _fail("data_transcript_consumption_record_invalid")
            if (
                record.get("status") != "consumed"
                or record.get("oracle_seal_sha256")
                != manifest.sha256
                or record.get("consumed_by_builder_run_id")
                != _managed_builder_run_id
                or record.get("consumed_by_experiment_id")
                != _managed_experiment_id
            ):
                _fail("data_transcript_consumption_record_invalid")
            return current

        preissue_state = engine.store.load(identity, recover=False)
        verify_base(expect_revision=preissue_state.revision)

        def add_preissue(current: ChallengeState) -> None:
            history_value = current.extra.get(
                DATA_TRANSCRIPT_STATE_KEY, {}
            )
            if (
                type(history_value) is not dict
                or history_value.get(attempt_id) != reservation
            ):
                _fail("data_transcript_reservation_binding_changed")
            next_history = copy.deepcopy(history_value)
            next_history[attempt_id] = copy.deepcopy(journal_preissue)
            current.extra[DATA_TRANSCRIPT_STATE_KEY] = next_history
            current.runs.extend(
                RunReference(
                    id=issue.run_id,
                    base_revision=preissue_state.revision,
                    status=RunStatus.CREATED,
                    request_path=run_request_paths[issue.run_id],
                    role="data_transcript",
                    origin=RunOrigin.MANAGED_TOOL,
                    configuration_epoch=configuration_epoch,
                    extra={
                        "data_transcript": {
                            "attempt_id": attempt_id,
                            "ordinal": issue.ordinal,
                            "phase": issue.phase,
                            "protocol": (
                                DATA_TRANSCRIPT_HOTPATH_PROTOCOL
                            ),
                        }
                    },
                )
                for issue in issues
            )
            current.artifacts.extend(
                copy.deepcopy(
                    tuple(
                        run_request_artifacts[issue.run_id]
                        for issue in issues
                    )
                )
            )

        preissued_state = engine.store.update(
            identity,
            add_preissue,
            expected_revision=preissue_state.revision,
            commit_guard=lambda: verify_base(
                expect_revision=preissue_state.revision
            ),
            pre_replace_guard=lambda: verify_base(
                expect_revision=preissue_state.revision
            ),
        )
        preissued_revision = preissued_state.revision
        uncommitted_run_ids.clear()

        def verify_published_state(
            current: ChallengeState,
            *,
            verify_captures: bool,
        ) -> None:
            transcript_history = current.extra.get(
                DATA_TRANSCRIPT_STATE_KEY
            )
            if (
                type(transcript_history) is not dict
                or transcript_history.get(attempt_id)
                != journal_preissue
            ):
                _fail("data_transcript_preissue_state_changed")
            current_builder = next(
                (
                    item
                    for item in current.runs
                    if item.id == _managed_builder_run_id
                ),
                None,
            )
            current_experiment = next(
                (
                    item
                    for item in current.experiments
                    if item.id == _managed_experiment_id
                ),
                None,
            )
            consumed_history = current.extra.get(
                MANAGED_ORACLE_PREISSUE_STATE_KEY
            )
            try:
                consumed_record = validate_public_record(
                    consumed_history.get(oracle_preissue_id)
                    if type(consumed_history) is dict
                    else None
                )
            except ManagedOraclePreissueError:
                _fail("data_transcript_consumption_record_invalid")
            if (
                current_builder is None
                or current_builder.role != "builder"
                or current_builder.origin is not RunOrigin.MANAGED_MODEL
                or current_builder.status is not RunStatus.COMPLETED
                or current_experiment is None
                or current_experiment.status
                is not ExperimentStatus.RUNNING
                or current_experiment.source_run_id
                != _managed_builder_run_id
                or consumed_record.get("status") != "consumed"
                or consumed_record.get("oracle_seal_sha256")
                != manifest.sha256
                or consumed_record.get(
                    "consumed_by_builder_run_id"
                )
                != _managed_builder_run_id
                or consumed_record.get(
                    "consumed_by_experiment_id"
                )
                != _managed_experiment_id
            ):
                _fail("data_transcript_published_binding_changed")
            run_index: dict[str, RunReference] = {}
            for run in current.runs:
                if run.id in {item.run_id for item in issues}:
                    if run.id in run_index:
                        _fail("data_transcript_preissued_run_changed")
                    run_index[run.id] = run
            if set(run_index) != {item.run_id for item in issues}:
                _fail("data_transcript_preissued_run_changed")
            artifact_index = {
                item.id: item for item in current.artifacts
            }
            for issue in issues:
                run = run_index.get(issue.run_id)
                request_artifact = run_request_artifacts[issue.run_id]
                if (
                    run is None
                    or run.status is not RunStatus.CREATED
                    or run.request_path
                    != run_request_paths[issue.run_id]
                    or run.base_revision != preissue_state.revision
                    or run.role != "data_transcript"
                    or run.origin is not RunOrigin.MANAGED_TOOL
                    or run.configuration_epoch != configuration_epoch
                    or run.extra.get("data_transcript")
                    != {
                        "attempt_id": attempt_id,
                        "ordinal": issue.ordinal,
                        "phase": issue.phase,
                        "protocol": DATA_TRANSCRIPT_HOTPATH_PROTOCOL,
                    }
                    or artifact_index.get(request_artifact.id)
                    != request_artifact
                ):
                    _fail("data_transcript_preissued_run_changed")
                request_payload = _read_artifact(
                    paths.root,
                    request_artifact,
                    maximum_bytes=256 * 1024,
                )
                if request_payload != run_request_bytes[issue.run_id]:
                    _fail("data_transcript_request_changed")
            if not verify_captures:
                return
            for capture in captures:
                for artifact, payload in zip(
                    capture.artifacts,
                    capture.artifact_payloads,
                    strict=True,
                ):
                    if (
                        _read_artifact(
                            paths.root,
                            artifact,
                            maximum_bytes=max(1, len(payload)),
                        )
                        != payload
                    ):
                        _fail(
                            "data_transcript_completed_evidence_changed"
                        )
                for locator, payload in (
                    (capture.result_path, capture.result_bytes),
                    (
                        capture.validation_path,
                        capture.validation_bytes,
                    ),
                ):
                    observed = read_bounded_regular(
                        paths.root,
                        locator,
                        maximum_bytes=256 * 1024,
                        expected_sha256=_sha256(payload),
                        expected_size=len(payload),
                    )
                    if observed != payload:
                        _fail(
                            "data_transcript_completed_evidence_changed"
                        )

        def verify_preissued(*, probe_capability: bool = False) -> None:
            current = verify_base(expect_revision=preissued_revision)
            verify_published_state(
                current,
                verify_captures=True,
            )
            if probe_capability:
                _probe_capability(engine, image_digest)

        lease = engine.lease_broker.acquire(
            DATA_TRANSCRIPT_RESOURCE,
            timeout=30.0,
            owner=f"{identity.key}:{attempt_id}",
        )
        if lease is None:
            _fail("data_transcript_resource_lease_unavailable")

        evidence_items: list[DataTranscriptReplayEvidence] = []
        seen_proof_identities: set[tuple[str, str, str]] = set()
        seen_clean_prefixes: set[str] = set()
        seen_sandbox_run_ids: set[str] = set()
        attempt_root = ensure_private_directory(
            paths.artifacts / "data-transcript" / attempt_id
        )
        captures_root = ensure_private_directory(
            attempt_root / "captures"
        )
        for position, (
            issue,
            (command, proof_inputs, proof_outputs),
        ) in enumerate(zip(issues, commands, strict=True), start=1):
            verify_preissued(probe_capability=True)
            result = client.run_clean_proof(
                command,
                proof_inputs=proof_inputs,
                proof_outputs=proof_outputs,
            )
            if not _complete_transport(result):
                _fail("data_transcript_transport_incomplete")
            if len(result.proof_outputs) != 4:
                _fail("data_transcript_output_count_invalid")
            producer_stdout_ref = client.register_artifact(
                result.stdout_path.removeprefix("/work/"),
                maximum_bytes=DATA_TRANSCRIPT_MAX_RESULT_BYTES,
            )
            producer_stderr_ref = client.register_artifact(
                result.stderr_path.removeprefix("/work/"),
                maximum_bytes=DATA_TRANSCRIPT_MAX_RESULT_BYTES,
            )
            clean_match = _CLEAN_STDOUT.fullmatch(
                producer_stdout_ref.locator
            )
            clean_prefix = (
                clean_match.group("prefix")
                if clean_match is not None
                else None
            )
            if (
                clean_prefix is None
                or producer_stderr_ref.locator
                != f"proof/{clean_prefix}/stderr.log"
                or producer_stdout_ref.scope_fingerprint
                != canonical_scope
                or producer_stderr_ref.scope_fingerprint
                != canonical_scope
                or any(
                    item.scope_fingerprint != canonical_scope
                    for item in result.proof_outputs
                )
                or type(result.run_id) is not str
                or not result.run_id
            ):
                _fail("data_transcript_scope_binding_invalid")
            proof_identity = (
                canonical_scope,
                result.run_id,
                clean_prefix,
            )
            if (
                proof_identity in seen_proof_identities
                or clean_prefix in seen_clean_prefixes
                or result.run_id in seen_sandbox_run_ids
            ):
                _fail("data_transcript_proof_identity_reused")
            seen_proof_identities.add(proof_identity)
            seen_clean_prefixes.add(clean_prefix)
            seen_sandbox_run_ids.add(result.run_id)
            producer_stdout = _read_scoped(
                proof_root,
                producer_stdout_ref,
                maximum_bytes=DATA_TRANSCRIPT_MAX_RESULT_BYTES,
            )
            producer_stderr = _read_scoped(
                proof_root,
                producer_stderr_ref,
                maximum_bytes=DATA_TRANSCRIPT_MAX_RESULT_BYTES,
            )
            output_payloads: list[bytes] = []
            for declaration, reference, (
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
                    declaration.name != expected_name
                    or reference.locator
                    != (
                        f"proof/{clean_prefix}/outputs/"
                        f"{expected_name}"
                    )
                ):
                    _fail("data_transcript_output_binding_invalid")
                output_payloads.append(
                    _read_scoped(
                        proof_root,
                        reference,
                        maximum_bytes=maximum_bytes,
                    )
                )
            if len(
                {
                    producer_stdout_ref.locator,
                    producer_stderr_ref.locator,
                    *(item.locator for item in result.proof_outputs),
                }
            ) != 6:
                _fail("data_transcript_output_binding_invalid")
            evidence = DataTranscriptReplayEvidence(
                document_bytes=producer_stdout,
                stdout_bytes=output_payloads[0],
                stderr_bytes=output_payloads[1],
                transcript_bytes=output_payloads[2],
                reset_proof_bytes=output_payloads[3],
            )
            evidence_items.append(evidence)
            payload_kinds = (
                (producer_stdout, "producer_stdout"),
                (producer_stderr, "producer_stderr"),
                *(
                    (output_payloads[index], _OUTPUT_SPECS[index][2])
                    for index in range(4)
                ),
            )
            durable_artifact_values: list[ArtifactReference] = []
            for index, (payload, kind) in enumerate(
                payload_kinds,
                start=1,
            ):
                artifact = _artifact_from_bytes(
                    engine=engine,
                    identity=identity,
                    artifact_id=issue.artifact_ids[index - 1],
                    destination=(
                        captures_root
                        / (
                            f"{position:02d}-{index:02d}-"
                            f"{kind}.bin"
                        )
                    ),
                    root=paths.root,
                    payload=payload,
                    run_id=issue.run_id,
                    kind=kind,
                    attempt_id=attempt_id,
                    phase=issue.phase,
                    ordinal=issue.ordinal,
                )
                durable_artifact_values.append(artifact)
                pending_artifacts.append(artifact)
            durable_artifacts = tuple(durable_artifact_values)
            result_document = {
                "artifact_sha256": {
                    artifact.extra["kind"]: artifact.sha256
                    for artifact in durable_artifacts
                },
                "oracle_preissue_sha256": manifest.sha256,
                "protocol": DATA_TRANSCRIPT_HOTPATH_PROTOCOL,
                "transport": {
                    "clean_prefix": clean_prefix,
                    "network": "none",
                    "one_shot": True,
                    "sandbox_method": "run_clean_proof",
                    "sandbox_run_id": result.run_id,
                    "scope_fingerprint": canonical_scope,
                },
            }
            validation_document = {
                "complete_transport": True,
                "network": "none",
                "oracle_preissue_sha256": manifest.sha256,
                "protocol": DATA_TRANSCRIPT_HOTPATH_PROTOCOL,
                "proof_identity": {
                    "clean_prefix": clean_prefix,
                    "sandbox_run_id": result.run_id,
                    "scope_fingerprint": canonical_scope,
                },
            }
            (
                result_path,
                validation_path,
                result_bytes,
                validation_bytes,
                result_artifact,
                validation_artifact,
            ) = _write_exact_run_sidecars(
                engine,
                identity,
                issue,
                attempt_id=attempt_id,
                result_document=result_document,
                validation_document=validation_document,
            )
            captures.append(
                _ReplayCapture(
                    issue=issue,
                    sandbox_run_id=result.run_id,
                    clean_prefix=clean_prefix,
                    scope_fingerprint=canonical_scope,
                    result_path=result_path,
                    validation_path=validation_path,
                    result_bytes=result_bytes,
                    validation_bytes=validation_bytes,
                    result_artifact=result_artifact,
                    validation_artifact=validation_artifact,
                    evidence=evidence,
                    artifacts=durable_artifacts,
                    artifact_payloads=tuple(
                        payload for payload, _kind in payload_kinds
                    ),
                )
            )

        expected_binding = DataTranscriptExpectedBinding(
            category=category,
            configuration_epoch=configuration_epoch,
            image_digest=image_digest,
            preissue_id=oracle_preissue_id,
            preissue_sha256=manifest.sha256,
            producer_sha256=DATA_TRANSCRIPT_PRODUCER_SHA256,
            recipe_sha256=recipe.sha256,
            recipe_size_bytes=len(recipe.canonical_bytes),
            peer_sha256=peer_artifact.sha256,
            peer_size_bytes=int(peer_artifact.size or 0),
            peer_data_sha256=peer_data_artifact.sha256,
            peer_data_size_bytes=int(peer_data_artifact.size or 0),
            reset_commitment_sha256=reset_commitment,
        )
        try:
            evaluation = evaluate_data_transcript_replays(
                tuple(evidence_items),
                expected_binding=expected_binding,
                recipe_bytes=recipe.canonical_bytes,
            )
        except DataTranscriptEvaluationError as error:
            raise DataTranscriptHotPathError(
                f"data_transcript_evaluation_rejected:{error.code}"
            ) from error
        if (
            evaluation.passed is not True
            or len(evaluation.positive_receipts) != 3
            or len(evaluation.control_receipts) != 3
        ):
            _fail("data_transcript_evaluation_matrix_invalid")
        evaluation_bytes = evaluation.canonical_bytes()
        if (
            len(evaluation_bytes) > DATA_TRANSCRIPT_MAX_RESULT_BYTES
            or evaluation_bytes
            != _canonical_bytes(evaluation.to_dict())
        ):
            _fail("data_transcript_evaluation_noncanonical")
        evaluation_artifact = _artifact_from_bytes(
            engine=engine,
            identity=identity,
            artifact_id=evaluation_artifact_id,
            destination=attempt_root / "evaluation.json",
            root=paths.root,
            payload=evaluation_bytes,
            run_id=issues[-1].run_id,
            kind="evaluation",
            attempt_id=attempt_id,
        )
        pending_artifacts.append(evaluation_artifact)
        evaluation_sha256 = _sha256(evaluation_bytes)
        completed_at = utc_now()
        proof_identities = [
            {
                "clean_prefix": capture.clean_prefix,
                "sandbox_run_id": capture.sandbox_run_id,
                "scope_fingerprint": capture.scope_fingerprint,
            }
            for capture in captures
        ]
        terminal_replays = [
            {
                "artifact_ids": list(capture.issue.artifact_ids),
                "ordinal": capture.issue.ordinal,
                "phase": capture.issue.phase,
                "request_artifact": _artifact_binding(
                    run_request_artifacts[capture.issue.run_id]
                ),
                "result_artifact": _artifact_binding(
                    capture.result_artifact
                ),
                "run_id": capture.issue.run_id,
                "validation_artifact": _artifact_binding(
                    capture.validation_artifact
                ),
            }
            for capture in captures
        ]
        final_journal = {
            **{
                key: copy.deepcopy(value)
                for key, value in journal_preissue.items()
                if key != "replays"
            },
            "completed_at": completed_at,
            "evaluation_artifact_id": evaluation_artifact.id,
            "evaluation_sha256": evaluation_sha256,
            "proof_identities": copy.deepcopy(proof_identities),
            "reason_code": str(evaluation.reason_code),
            "replays": terminal_replays,
            "status": "passed",
            "terminal": True,
            "unique_clean_prefix_count": len(
                {item["clean_prefix"] for item in proof_identities}
            ),
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
            "unique_sandbox_run_id_count": len(
                {
                    item["sandbox_run_id"]
                    for item in proof_identities
                }
            ),
        }
        terminal_sidecar_artifacts = tuple(
            artifact
            for capture in captures
            for artifact in (
                capture.result_artifact,
                capture.validation_artifact,
            )
        )
        evidence_artifact_ids = tuple(
            (
                *(
                    run_request_artifacts[issue.run_id].id
                    for issue in issues
                ),
                *(
                    artifact.id for artifact in pending_artifacts
                ),
                *(
                    artifact.id
                    for artifact in terminal_sidecar_artifacts
                ),
            )
        )
        parent_result = _typed_gate_result(
            passed=True,
            reason_codes=(str(evaluation.reason_code),),
            evaluation_sha256=evaluation_sha256,
            evidence_artifact_ids=evidence_artifact_ids,
            evidence_run_ids=tuple(
                issue.run_id for issue in issues
            ),
            execution_error_type=None,
        )

        def commit_final(current: ChallengeState) -> None:
            transcript_history = current.extra.get(
                DATA_TRANSCRIPT_STATE_KEY
            )
            if (
                type(transcript_history) is not dict
                or transcript_history.get(attempt_id)
                != journal_preissue
            ):
                _fail("data_transcript_preissue_changed_before_commit")
            run_index = {item.id: item for item in current.runs}
            for capture in captures:
                run = run_index.get(capture.issue.run_id)
                if run is None or run.status is not RunStatus.CREATED:
                    _fail("data_transcript_run_changed_before_commit")
                run.status = RunStatus.COMPLETED
                run.result_path = capture.result_path
                run.validation_path = capture.validation_path
                run.extra["data_transcript"].update(
                    {
                        "proof_identity": {
                            "clean_prefix": capture.clean_prefix,
                            "sandbox_run_id": capture.sandbox_run_id,
                            "scope_fingerprint": (
                                capture.scope_fingerprint
                            ),
                        },
                        "terminal": True,
                    }
                )
            current.artifacts.extend(
                copy.deepcopy(pending_artifacts)
            )
            current.artifacts.extend(
                copy.deepcopy(terminal_sidecar_artifacts)
            )
            next_history = copy.deepcopy(transcript_history)
            next_history[attempt_id] = final_journal
            current.extra[DATA_TRANSCRIPT_STATE_KEY] = next_history
            _terminalize_parent_experiment(
                current,
                experiment_id=_managed_experiment_id,
                builder_run_id=_managed_builder_run_id,
                completed_at=completed_at,
                passed=True,
                result=parent_result,
            )

        verify_preissued(probe_capability=True)
        final_state = engine.store.update(
            identity,
            commit_final,
            expected_revision=preissued_revision,
            commit_guard=lambda: verify_preissued(
                probe_capability=True
            ),
            pre_replace_guard=lambda: verify_preissued(),
        )
        if (
            final_state.status is not before_status
            or tuple(item.id for item in final_state.candidates)
            != before_candidates
            or tuple(item.id for item in final_state.submissions)
            != before_submissions
        ):
            _fail("data_transcript_authority_escape")
        pending_artifacts.clear()
        return final_state, evaluation
    except BaseException as failure:
        if preissued_revision is not None and journal_preissue is not None:
            try:
                current_after_failure = engine.store.load(
                    identity,
                    recover=False,
                )
                current_history = current_after_failure.extra.get(
                    DATA_TRANSCRIPT_STATE_KEY
                )
                current_journal = (
                    current_history.get(attempt_id)
                    if type(current_history) is dict
                    else None
                )
                if (
                    type(current_journal) is dict
                    and current_journal.get("terminal") is True
                    and current_journal.get("status")
                    in {"passed", "failed"}
                ):
                    pending_artifacts.clear()
                else:
                    verify_published_state(
                        current_after_failure,
                        verify_captures=False,
                    )
                    _terminalize_published_attempt(
                        engine,
                        identity,
                        journal_preissue,
                        failure,
                    )
            except BaseException as terminal_error:
                failure.add_note(
                    "data transcript failure terminalization failed: "
                    f"{type(terminal_error).__name__}"
                )
        else:
            try:
                _cleanup_uncommitted_run_directories(
                    engine,
                    identity,
                    tuple(uncommitted_run_ids),
                )
                uncommitted_run_ids.clear()
                _terminalize_reserved_attempt(
                    engine,
                    identity,
                    reservation,
                    failure,
                )
            except BaseException as terminal_error:
                failure.add_note(
                    "data transcript reservation cleanup failed: "
                    f"{type(terminal_error).__name__}"
                )
        if pending_artifacts:
            try:
                engine._cleanup_uncommitted_artifacts(
                    identity,
                    tuple(pending_artifacts),
                    cause=failure,
                )
            except BaseException as cleanup_error:
                failure.add_note(
                    "data transcript artifact cleanup failed: "
                    f"{type(cleanup_error).__name__}"
                )
        raise
    finally:
        try:
            if lease is not None:
                lease.release()
        finally:
            if private_workspace is not None:
                private_workspace.cleanup()


__all__ = [
    "DATA_TRANSCRIPT_CAPABILITY",
    "DATA_TRANSCRIPT_HOTPATH_PROTOCOL",
    "DATA_TRANSCRIPT_PRODUCER_PATH",
    "DATA_TRANSCRIPT_PRODUCER_SHA256",
    "DATA_TRANSCRIPT_STATE_KEY",
    "DataTranscriptHotPathError",
    "prove_data_transcript",
    "recover_data_transcript_attempts",
]
