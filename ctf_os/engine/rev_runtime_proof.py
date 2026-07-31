"""Candidate-free accepted-input proof for hash-bound Rev runtimes.

This hot path extends the existing fixed 3+3 accepted-input oracle to runtime
targets selected by :mod:`ctf_os.contracts.rev_runtime_v1`.  The runtime
document is data only.  Target bytes come exclusively from an immutable
``incoming/`` inventory snapshot, while the accepted input stays in an
engine-private artifact and is supplied to six independent clean proofs as
stdin.

Nothing in this module can create a flag candidate, authorize submission, or
change challenge status.  Canonical/public state receives only commitment
hashes, sizes, counts, fixed authority-denial markers, and a verdict.  Oracle
contents, accepted bytes, raw streams, and execution pointers remain in
engine-private artifacts.
"""

from __future__ import annotations

import copy
import os
import re
import secrets
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Mapping, Sequence

from ctf_os.adapters import get_adapter
from ctf_os.contracts.rev_runtime_v1 import (
    REV_RUNTIME_V1_FORMATS,
    REV_RUNTIME_V1_MAX_DOCUMENT_BYTES,
    REV_RUNTIME_V1_MAX_FILE_BYTES,
    REV_RUNTIME_V1_MAX_DEPENDENCIES,
    REV_RUNTIME_V1_RUNTIMES,
    RevRuntimeV1Error,
    RevRuntimeV1File,
    RevRuntimeV1Spec,
)
from ctf_os.director.resources import tool_profile
from ctf_os.engine.rev_acceptance import (
    REV_ACCEPTANCE_MAX_EVIDENCE_BYTES,
    REV_ACCEPTANCE_MAX_INPUT_BYTES,
    REV_ACCEPTANCE_MAX_SPEC_BYTES,
    REV_ACCEPTANCE_MAX_STREAM_BYTES,
    REV_ACCEPTANCE_OPERATOR_SPEC_PROTOCOL,
    REV_ACCEPTANCE_SCHEMA_VERSION,
    RevAcceptanceContractError,
    RevAcceptanceExpectation,
    RevAcceptanceOperatorSpec,
    build_rev_acceptance_plan,
    canonical_json_bytes,
    evaluate_rev_acceptance,
    sha256,
    validate_rev_acceptance_expected_oracle,
    validate_rev_acceptance_evaluation,
)
from ctf_os.models import (
    ArtifactReference,
    ChallengeIdentity,
    ChallengeState,
    ChallengeStatus,
    Experiment,
    ExperimentKind,
    ExperimentStatus,
    RunOrigin,
    RunReference,
    RunStatus,
    utc_now,
)
from ctf_os.sandbox import CommandSpec, NetworkPolicy, ProofInput
from ctf_os.sandbox.files import (
    SafeFileError,
    copy_bounded_regular,
    ensure_private_directory,
    ensure_relative_directory,
    normalize_locator,
    read_bounded_regular,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.stages.ingest import inventory_challenge
from ctf_os.store import ChallengeLock, LockTimeout
from ctf_os.store.atomic import (
    StrictJSONError,
    atomic_write_bytes,
    strict_json_loads,
)

if TYPE_CHECKING:
    from ctf_os.engine.challenge import ChallengeEngine


REV_RUNTIME_PROOF_PROTOCOL = "ctfos.rev.runtime-proof.v1"
REV_RUNTIME_PROOF_SCHEMA_VERSION = 1
REV_RUNTIME_PROOF_RESULT_KEY = "rev_runtime_proof"
REV_RUNTIME_PROOF_EXECUTOR = "engine.rev_runtime_proof.v1"
REV_RUNTIME_PROOF_MAX_TIMEOUT_SECONDS = 3600
REV_RUNTIME_EXEC_CAPABILITY = "rev_runtime_exec_v1"
REV_RUNTIME_EXEC_SHA256 = (
    "9b2544102e8fa2ec7930b09f3d8b650041bdf782eff6b5bab0454895194d0d79"
)
REV_RUNTIME_EXEC_ATTESTATION = {
    "schema_version": 1,
    "contract_id": "ctfos.rev.runtime_exec",
    "contract_version": 1,
    "path": "/opt/ctf-templates/rev/runtime_exec.py",
    "sha256": REV_RUNTIME_EXEC_SHA256,
}
REV_RUNTIME_EXEC_ARGV = (
    "/usr/bin/python3",
    "/opt/ctf-templates/rev/runtime_exec.py",
    "--spec",
    "/work/oracle/runtime-spec.json",
    "--input",
    "/work/oracle/accepted-input.bin",
)
_DIGEST_PIN = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_AUTHORITIES = {
    "automatic_submission_authorized": False,
    "candidate_authorized": False,
    "challenge_status_transition_authorized": False,
    "flag_proven": False,
}


class RevRuntimeProofError(RuntimeError):
    """Stable fail-closed runtime-proof error."""

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

    def binding(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "source_locator": self.source_locator,
        }


@dataclass(frozen=True, slots=True)
class _RunRecord:
    run: RunReference
    artifacts: tuple[ArtifactReference, ArtifactReference]
    record: dict[str, object]


def _new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(16)}"


def _artifact_extra(
    *,
    experiment_id: str,
    kind: str,
    **values: object,
) -> dict[str, object]:
    return {
        "context_visibility": "engine_private",
        "engine_executor": REV_RUNTIME_PROOF_EXECUTOR,
        "experiment_id": experiment_id,
        "kind": kind,
        "protocol": REV_RUNTIME_PROOF_PROTOCOL,
        **values,
    }


def _file_binding(
    root: Path,
    path: Path,
    *,
    maximum_bytes: int,
) -> tuple[str, int]:
    relative = path.relative_to(root).as_posix()
    with tempfile.TemporaryDirectory(
        prefix=".ctfos-rev-runtime-file-binding-",
        dir=root,
    ) as temporary:
        immutable = copy_bounded_regular(
            root,
            relative,
            Path(temporary) / "bound.bin",
            maximum_bytes=maximum_bytes,
            mode=0o400,
        )
    return immutable.sha256, immutable.size_bytes


def _snapshot_workspace(
    engine: ChallengeEngine,
    state: ChallengeState,
    client: object,
    *,
    locator: str,
    destination: Path,
    artifact_id: str,
    maximum_bytes: int,
) -> _Snapshot:
    try:
        immutable = engine._snapshot_workspace_file(
            state,
            client,
            locator,
            destination,
        )
    except Exception as error:
        raise RevRuntimeProofError(
            "runtime_workspace_snapshot_failed"
        ) from error
    if immutable.size_bytes > maximum_bytes:
        raise RevRuntimeProofError("runtime_workspace_snapshot_too_large")
    return _Snapshot(
        artifact_id=artifact_id,
        path=immutable.path.relative_to(
            engine.store.challenge_paths(state.identity).root
        ).as_posix(),
        sha256=immutable.sha256,
        size_bytes=immutable.size_bytes,
        source_locator=locator,
    )


def _operator_input_path(
    engine: ChallengeEngine,
    accepted_input_path: Path,
) -> tuple[Path, Path]:
    """Return lexical/resolved paths for one operator-private input.

    The accepted input is a host-side operator secret, not challenge input.
    It must never pass through the model-visible workspace tree.
    """

    if not isinstance(accepted_input_path, Path):
        raise RevRuntimeProofError("runtime_private_input_path_invalid")
    lexical = accepted_input_path
    if not lexical.is_absolute():
        lexical = Path.cwd() / lexical
    lexical = Path(os.path.abspath(os.fspath(lexical)))
    try:
        resolved = lexical.resolve(strict=True)
        workspace_root = engine.store.workspace_root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RevRuntimeProofError(
            "runtime_private_input_path_invalid"
        ) from error
    if resolved == workspace_root or resolved.is_relative_to(workspace_root):
        raise RevRuntimeProofError(
            "runtime_private_input_boundary_invalid"
        )
    return lexical, resolved


def _snapshot_operator_input(
    engine: ChallengeEngine,
    state: ChallengeState,
    *,
    accepted_input_path: Path,
    destination: Path,
    artifact_id: str,
) -> tuple[_Snapshot, bytes]:
    """Descriptor-read one private operator file into engine-owned storage."""

    lexical, resolved = _operator_input_path(engine, accepted_input_path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lexical, flags)
    except OSError as error:
        raise RevRuntimeProofError(
            "runtime_private_input_open_failed"
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o077
            or before.st_nlink != 1
            or not 0
            <= before.st_size
            <= REV_ACCEPTANCE_MAX_INPUT_BYTES
        ):
            raise RevRuntimeProofError(
                "runtime_private_input_metadata_invalid"
            )
        try:
            resolved_stat = os.stat(resolved, follow_symlinks=False)
            descriptor_target = Path(
                os.readlink(f"/proc/self/fd/{descriptor}")
            ).resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise RevRuntimeProofError(
                "runtime_private_input_identity_invalid"
            ) from error
        if (
            descriptor_target != resolved
            or (resolved_stat.st_dev, resolved_stat.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            raise RevRuntimeProofError(
                "runtime_private_input_identity_invalid"
            )

        payload = bytearray()
        while len(payload) <= REV_ACCEPTANCE_MAX_INPUT_BYTES:
            block = os.read(
                descriptor,
                min(
                    1024 * 1024,
                    REV_ACCEPTANCE_MAX_INPUT_BYTES + 1 - len(payload),
                ),
            )
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
        )
        try:
            final_resolved = lexical.resolve(strict=True)
            final_stat = os.stat(final_resolved, follow_symlinks=False)
        except (OSError, RuntimeError) as error:
            raise RevRuntimeProofError(
                "runtime_private_input_changed"
            ) from error
        if (
            len(payload) > REV_ACCEPTANCE_MAX_INPUT_BYTES
            or len(payload) != after.st_size
            or before_identity != after_identity
            or final_resolved != resolved
            or (final_stat.st_dev, final_stat.st_ino)
            != (after.st_dev, after.st_ino)
        ):
            raise RevRuntimeProofError(
                "runtime_private_input_changed"
            )
        immutable_payload = bytes(payload)
    except OSError as error:
        raise RevRuntimeProofError(
            "runtime_private_input_read_failed"
        ) from error
    finally:
        os.close(descriptor)

    atomic_write_bytes(destination, immutable_payload, mode=0o400)
    challenge_root = engine.store.challenge_paths(state.identity).root
    relative = destination.relative_to(challenge_root).as_posix()
    try:
        copied = read_bounded_regular(
            challenge_root,
            relative,
            maximum_bytes=REV_ACCEPTANCE_MAX_INPUT_BYTES,
            expected_sha256=sha256(immutable_payload),
            expected_size=len(immutable_payload),
        )
    except (OSError, SafeFileError) as error:
        raise RevRuntimeProofError(
            "runtime_private_input_snapshot_failed"
        ) from error
    if copied != immutable_payload:
        raise RevRuntimeProofError(
            "runtime_private_input_snapshot_failed"
        )
    return (
        _Snapshot(
            artifact_id=artifact_id,
            path=relative,
            sha256=sha256(immutable_payload),
            size_bytes=len(immutable_payload),
            source_locator="operator-private-file",
        ),
        immutable_payload,
    )


def _snapshot_proof_stream(
    client: object,
    *,
    workspace_root: Path,
    locator: str,
    destination: Path,
) -> object:
    """Promote one stream without ever copying beyond the stream bound."""

    try:
        reference = client.register_artifact(
            locator,
            maximum_bytes=REV_ACCEPTANCE_MAX_STREAM_BYTES,
        )
        if reference.scope_fingerprint != client.scope_fingerprint:
            raise RevRuntimeProofError(
                "runtime_stream_scope_changed"
            )
        return copy_bounded_regular(
            workspace_root,
            reference.locator,
            destination,
            maximum_bytes=REV_ACCEPTANCE_MAX_STREAM_BYTES,
            expected_sha256=reference.sha256,
            expected_size=reference.size_bytes,
            mode=0o400,
        )
    except RevRuntimeProofError:
        raise
    except (OSError, SafeFileError, TypeError, ValueError) as error:
        raise RevRuntimeProofError(
            "runtime_stream_snapshot_failed"
        ) from error


def _require_workspace_current(
    client: object,
    snapshot: _Snapshot,
) -> None:
    try:
        reference = client.register_artifact(
            snapshot.source_locator,
            maximum_bytes=snapshot.size_bytes + 1,
        )
    except Exception as error:
        raise RevRuntimeProofError(
            "runtime_workspace_binding_changed"
        ) from error
    if (
        reference.scope_fingerprint != client.scope_fingerprint
        or reference.sha256 != snapshot.sha256
        or reference.size_bytes != snapshot.size_bytes
    ):
        raise RevRuntimeProofError("runtime_workspace_binding_changed")


def _runtime_files(
    spec: RevRuntimeV1Spec,
) -> tuple[RevRuntimeV1File, ...]:
    return (spec.source, *spec.dependencies)


def _source_closure(spec: RevRuntimeV1Spec) -> list[dict[str, object]]:
    return [item.to_dict() for item in _runtime_files(spec)]


def _source_closure_sha256(spec: RevRuntimeV1Spec) -> str:
    return sha256(canonical_json_bytes(_source_closure(spec)))


def _require_incoming_current(
    engine: ChallengeEngine,
    state: ChallengeState,
    spec: RevRuntimeV1Spec,
    *,
    expected_manifest_sha256: str,
) -> None:
    try:
        inventory = inventory_challenge(engine.challenge_input(state.identity))
    except (OSError, ValueError) as error:
        raise RevRuntimeProofError(
            "runtime_source_inventory_failed"
        ) from error
    indexed = {item.path: item for item in inventory.files}
    if (
        inventory.manifest_sha256 != expected_manifest_sha256
        or state.metadata.get("source_manifest_sha256")
        != expected_manifest_sha256
    ):
        raise RevRuntimeProofError("runtime_source_binding_changed")
    for expected in _runtime_files(spec):
        current = indexed.get(expected.path)
        if (
            current is None
            or current.sha256 != expected.sha256
            or current.size != expected.size_bytes
        ):
            raise RevRuntimeProofError("runtime_source_binding_changed")


def _verify_source_snapshot(
    challenge_root: Path,
    spec: RevRuntimeV1Spec,
) -> None:
    try:
        inventory = inventory_challenge(challenge_root)
    except (OSError, ValueError) as error:
        raise RevRuntimeProofError(
            "runtime_source_snapshot_invalid"
        ) from error
    observed = {
        item.path: (item.sha256, item.size) for item in inventory.files
    }
    expected = {
        item.path: (item.sha256, item.size_bytes)
        for item in _runtime_files(spec)
    }
    if observed != expected:
        raise RevRuntimeProofError("runtime_source_snapshot_invalid")


def _build_source_snapshot(
    engine: ChallengeEngine,
    state: ChallengeState,
    spec: RevRuntimeV1Spec,
    challenge_root: Path,
) -> None:
    incoming = engine.challenge_input(state.identity)
    ensure_private_directory(challenge_root)
    try:
        for item in _runtime_files(spec):
            parent = PurePosixPath(item.path).parent
            if parent != PurePosixPath("."):
                ensure_relative_directory(
                    challenge_root,
                    parent.as_posix(),
                )
            copy_bounded_regular(
                incoming,
                item.path,
                challenge_root / item.path,
                maximum_bytes=REV_RUNTIME_V1_MAX_FILE_BYTES,
                expected_sha256=item.sha256,
                expected_size=item.size_bytes,
                mode=0o500,
            )
        _verify_source_snapshot(challenge_root, spec)
        for directory, subdirectories, _files in os.walk(
            challenge_root,
            topdown=False,
            followlinks=False,
        ):
            os.chmod(directory, 0o500)
            for name in subdirectories:
                candidate = Path(directory) / name
                if candidate.is_symlink():
                    raise RevRuntimeProofError(
                        "runtime_source_snapshot_invalid"
                    )
    except RevRuntimeProofError:
        raise
    except (OSError, SafeFileError, ValueError) as error:
        raise RevRuntimeProofError(
            "runtime_source_snapshot_failed"
        ) from error


def _unlock_source_snapshot(challenge_root: Path) -> None:
    """Restore only engine-created temporary directories for safe cleanup."""

    try:
        for directory, subdirectories, _files in os.walk(
            challenge_root,
            topdown=False,
            followlinks=False,
        ):
            for name in subdirectories:
                candidate = Path(directory) / name
                if not candidate.is_symlink():
                    os.chmod(candidate, 0o700)
            os.chmod(directory, 0o700)
    except OSError:
        # TemporaryDirectory has its own permission-recovery cleanup.  This
        # helper must never mask the proof result or an active interruption.
        pass


def _probe_runtime_capability(
    engine: ChallengeEngine,
    image_digest: str,
) -> dict[str, object]:
    try:
        if getattr(engine, "_capability_probe_accepts_timeout", False):
            report = engine._capability_probe(
                image_digest,
                timeout_seconds=30,
            )
        else:
            report = engine._capability_probe(image_digest)
    except Exception as error:
        raise RevRuntimeProofError(
            "runtime_capability_probe_failed"
        ) from error
    if not isinstance(report, Mapping):
        raise RevRuntimeProofError("runtime_capability_attestation_invalid")
    attestations = report.get("attestations")
    available = report.get("available")
    missing = report.get("missing")
    selected_attestation = (
        attestations.get(REV_RUNTIME_EXEC_CAPABILITY)
        if isinstance(attestations, Mapping)
        else None
    )
    if (
        report.get("ok") is not True
        or report.get("image_digest") != image_digest
        or not isinstance(attestations, Mapping)
        or not isinstance(selected_attestation, Mapping)
        or dict(selected_attestation) != REV_RUNTIME_EXEC_ATTESTATION
        or not isinstance(available, (list, tuple))
        or REV_RUNTIME_EXEC_CAPABILITY not in available
        or not isinstance(missing, (list, tuple))
        or REV_RUNTIME_EXEC_CAPABILITY in missing
    ):
        raise RevRuntimeProofError(
            "runtime_capability_attestation_invalid"
        )
    return copy.deepcopy(REV_RUNTIME_EXEC_ATTESTATION)


def _complete_transport(result: object) -> bool:
    return (
        result is not None
        and result.timed_out is False
        and type(result.exit_code) is int
        and 0 <= result.exit_code <= 255
        and result.stdout_capture_complete is True
        and result.stderr_capture_complete is True
        and result.stdout_truncation_known is True
        and result.stderr_truncation_known is True
        and result.stdout_truncated is False
        and result.stderr_truncated is False
        and result.stdout_error is None
        and result.stderr_error is None
        and result.orchestration_error is None
        and result.stream_capture_error is None
    )


def _stream_capture_matches(
    result: object,
    *,
    stream: str,
    size_bytes: int,
) -> bool:
    return (
        getattr(result, f"{stream}_bytes", None) == size_bytes
        and getattr(result, f"{stream}_stored_bytes", None) == size_bytes
        and type(getattr(result, f"{stream}_limit_bytes", None)) is int
        and getattr(result, f"{stream}_limit_bytes")
        <= REV_ACCEPTANCE_MAX_STREAM_BYTES
        and size_bytes
        <= getattr(result, f"{stream}_limit_bytes")
        and size_bytes <= REV_ACCEPTANCE_MAX_STREAM_BYTES
    )


def _normalized_result_locator(value: object) -> str:
    if type(value) is not str or not value.startswith("/work/"):
        raise RevRuntimeProofError("runtime_result_locator_invalid")
    try:
        return normalize_locator(value.removeprefix("/work/"))
    except SafeFileError as error:
        raise RevRuntimeProofError(
            "runtime_result_locator_invalid"
        ) from error


def _accepted_input_disclosed(
    spec: RevRuntimeV1Spec,
    accepted_input: bytes,
) -> bool:
    if not accepted_input:
        return False
    try:
        text = accepted_input.decode("utf-8", errors="strict")
    except UnicodeError:
        return accepted_input in spec.canonical_bytes
    if not text:
        return False
    semantic_strings = [
        *spec.argv,
        spec.source.path,
        *(item.path for item in spec.dependencies),
        spec.options.working_directory,
        *(
            value
            for value in (
                spec.options.architecture,
                spec.options.main_class,
                spec.options.qemu_ld_prefix,
                spec.options.wasm_entrypoint,
            )
            if value is not None
        ),
    ]
    if any(text in value for value in semantic_strings):
        return True
    # Reject exact reconstruction across argv token boundaries.  This is a
    # secondary structural check; the primary invariant is that the complete
    # spec is frozen before the private operator file is opened.
    for start in range(len(spec.argv)):
        combined = ""
        for value in spec.argv[start:]:
            combined += value
            if combined == text:
                return True
            if len(combined) >= len(text):
                break
    return False


def _runtime_evaluation(
    *,
    acceptance: Mapping[str, object],
    runtime_spec: RevRuntimeV1Spec,
    runtime_spec_snapshot: _Snapshot,
    accepted_input_snapshot: _Snapshot,
    expected_oracle: Mapping[str, object],
    source_manifest_sha256: str,
    image_digest: str,
    attestation: Mapping[str, object],
    scope_fingerprint: str,
    records: Sequence[Mapping[str, object]],
    additional_reason_codes: Sequence[str],
) -> dict[str, object]:
    reasons = list(acceptance.get("reason_codes", []))
    reasons.extend(additional_reason_codes)
    reasons = list(dict.fromkeys(reasons))
    evaluation = {
        "accepted_input": {
            "artifact_id": accepted_input_snapshot.artifact_id,
            "sha256": accepted_input_snapshot.sha256,
            "size_bytes": accepted_input_snapshot.size_bytes,
        },
        "acceptance_evaluation": copy.deepcopy(dict(acceptance)),
        "authorities": dict(_AUTHORITIES),
        "expected_oracle_sha256": sha256(
            canonical_json_bytes(dict(expected_oracle))
        ),
        "expected_oracle": copy.deepcopy(dict(expected_oracle)),
        "image_digest": image_digest,
        "passed": not reasons,
        "proof_scope_fingerprint": scope_fingerprint,
        "protocol": REV_RUNTIME_PROOF_PROTOCOL,
        "reason_codes": reasons,
        "records": [copy.deepcopy(dict(item)) for item in records],
        "runner_attestation": copy.deepcopy(dict(attestation)),
        "runtime_spec": {
            "argv_sha256": sha256(
                canonical_json_bytes(list(runtime_spec.argv))
            ),
            "artifact_id": runtime_spec_snapshot.artifact_id,
            "format": runtime_spec.format,
            "runtime": runtime_spec.runtime,
            "sha256": runtime_spec_snapshot.sha256,
            "size_bytes": runtime_spec_snapshot.size_bytes,
        },
        "schema_version": REV_RUNTIME_PROOF_SCHEMA_VERSION,
        "source_closure": _source_closure(runtime_spec),
        "source_closure_sha256": _source_closure_sha256(runtime_spec),
        "source_manifest_sha256": source_manifest_sha256,
    }
    payload = canonical_json_bytes(evaluation)
    if len(payload) > REV_ACCEPTANCE_MAX_EVIDENCE_BYTES:
        raise RevRuntimeProofError("runtime_evaluation_too_large")
    return evaluation


def _validate_private_rev_runtime_proof_evaluation(
    value: object,
) -> dict[str, object]:
    """Strictly validate the engine-private runtime evaluation."""

    expected_keys = {
        "accepted_input",
        "acceptance_evaluation",
        "authorities",
        "expected_oracle_sha256",
        "expected_oracle",
        "image_digest",
        "passed",
        "proof_scope_fingerprint",
        "protocol",
        "reason_codes",
        "records",
        "runner_attestation",
        "runtime_spec",
        "schema_version",
        "source_closure",
        "source_closure_sha256",
        "source_manifest_sha256",
    }
    if type(value) is not dict or set(value) != expected_keys:
        raise RevRuntimeProofError("runtime_evaluation_schema_invalid")
    if (
        value["protocol"] != REV_RUNTIME_PROOF_PROTOCOL
        or value["schema_version"] != REV_RUNTIME_PROOF_SCHEMA_VERSION
        or value["authorities"] != _AUTHORITIES
        or type(value["passed"]) is not bool
        or type(value["reason_codes"]) is not list
        or value["passed"] is not (not value["reason_codes"])
        or value["runner_attestation"] != REV_RUNTIME_EXEC_ATTESTATION
        or type(value["image_digest"]) is not str
        or _DIGEST_PIN.fullmatch(value["image_digest"]) is None
        or any(
            type(value[field]) is not str
            or _SHA256.fullmatch(value[field]) is None
            for field in (
                "expected_oracle_sha256",
                "source_closure_sha256",
                "source_manifest_sha256",
            )
        )
        or type(value["proof_scope_fingerprint"]) is not str
        or _SHA256.fullmatch(value["proof_scope_fingerprint"]) is None
        or type(value["records"]) is not list
        or len(value["records"]) != 6
        or any(
            type(code) is not str or not code
            for code in value["reason_codes"]
        )
        or len(set(value["reason_codes"]))
        != len(value["reason_codes"])
    ):
        raise RevRuntimeProofError("runtime_evaluation_invalid")
    accepted = value["accepted_input"]
    runtime_spec = value["runtime_spec"]
    if (
        type(accepted) is not dict
        or set(accepted) != {"artifact_id", "sha256", "size_bytes"}
        or type(accepted["artifact_id"]) is not str
        or type(accepted["sha256"]) is not str
        or _SHA256.fullmatch(accepted["sha256"]) is None
        or type(accepted["size_bytes"]) is not int
        or not 0 <= accepted["size_bytes"] <= REV_ACCEPTANCE_MAX_INPUT_BYTES
        or type(runtime_spec) is not dict
        or set(runtime_spec)
        != {
            "argv_sha256",
            "artifact_id",
            "format",
            "runtime",
            "sha256",
            "size_bytes",
        }
        or any(
            type(runtime_spec[field]) is not str
            for field in ("artifact_id", "format", "runtime")
        )
        or runtime_spec["format"] not in REV_RUNTIME_V1_FORMATS
        or runtime_spec["runtime"] not in REV_RUNTIME_V1_RUNTIMES
        or any(
            type(runtime_spec[field]) is not str
            or _SHA256.fullmatch(runtime_spec[field]) is None
            for field in ("argv_sha256", "sha256")
        )
        or type(runtime_spec["size_bytes"]) is not int
        or not 1
        <= runtime_spec["size_bytes"]
        <= REV_RUNTIME_V1_MAX_DOCUMENT_BYTES
    ):
        raise RevRuntimeProofError("runtime_evaluation_binding_invalid")
    try:
        normalized_oracle = validate_rev_acceptance_expected_oracle(
            value["expected_oracle"]
        )
        if (
            normalized_oracle != value["expected_oracle"]
            or sha256(canonical_json_bytes(normalized_oracle))
            != value["expected_oracle_sha256"]
        ):
            raise RevRuntimeProofError(
                "runtime_evaluation_oracle_invalid"
            )
        acceptance = validate_rev_acceptance_evaluation(
            value["acceptance_evaluation"]
        )
        raw_closure = value["source_closure"]
        if (
            type(raw_closure) is not list
            or not 1
            <= len(raw_closure)
            <= REV_RUNTIME_V1_MAX_DEPENDENCIES + 1
        ):
            raise RevRuntimeProofError(
                "runtime_evaluation_source_invalid"
            )
        closure = tuple(
            RevRuntimeV1File.from_mapping(item)
            for item in raw_closure
        )
        dependency_paths = tuple(
            item.path for item in closure[1:]
        )
        if (
            dependency_paths != tuple(sorted(dependency_paths))
            or len({item.path for item in closure}) != len(closure)
            or sha256(canonical_json_bytes(raw_closure))
            != value["source_closure_sha256"]
            or acceptance["source_manifest_sha256"]
            != value["source_manifest_sha256"]
            or acceptance["source_sha256"] != closure[0].sha256
            or acceptance["source_size_bytes"]
            != closure[0].size_bytes
            or acceptance["image_digest"] != value["image_digest"]
        ):
            raise RevRuntimeProofError(
                "runtime_evaluation_source_invalid"
            )
        expected_record_keys = {
            "observation",
            "request_path",
            "request_sha256",
            "request_size_bytes",
            "result_path",
            "result_sha256",
            "result_size_bytes",
            "sandbox_run_id",
            "scope_fingerprint",
            "stderr_locator",
            "stdout_locator",
            "validation_path",
            "validation_sha256",
            "validation_size_bytes",
        }
        sandbox_ids: set[str] = set()
        proof_locators: set[str] = set()
        durable_paths: set[str] = set()
        sandbox_reused = False
        for index, record in enumerate(value["records"]):
            if (
                type(record) is not dict
                or set(record) != expected_record_keys
                or record["observation"]
                != acceptance["observations"][index]
                or record["scope_fingerprint"]
                != value["proof_scope_fingerprint"]
                or type(record["sandbox_run_id"]) is not str
                or not record["sandbox_run_id"]
            ):
                raise RevRuntimeProofError(
                    "runtime_evaluation_record_invalid"
                )
            if record["sandbox_run_id"] in sandbox_ids:
                sandbox_reused = True
            sandbox_ids.add(record["sandbox_run_id"])
            for stream in ("stdout", "stderr"):
                locator = record[f"{stream}_locator"]
                if (
                    type(locator) is not str
                    or normalize_locator(locator) != locator
                    or locator in proof_locators
                ):
                    sandbox_reused = True
                proof_locators.add(locator)
            for prefix in ("request", "result", "validation"):
                path = record[f"{prefix}_path"]
                digest = record[f"{prefix}_sha256"]
                size = record[f"{prefix}_size_bytes"]
                if (
                    type(path) is not str
                    or normalize_locator(path) != path
                    or path in durable_paths
                    or type(digest) is not str
                    or _SHA256.fullmatch(digest) is None
                    or type(size) is not int
                    or not 0 <= size <= REV_ACCEPTANCE_MAX_EVIDENCE_BYTES
                ):
                    raise RevRuntimeProofError(
                        "runtime_evaluation_record_invalid"
                    )
                durable_paths.add(path)
        expected_reasons = list(acceptance["reason_codes"])
        independently_derived_reasons: list[str] = []
        run_ids: set[str] = set()
        receipt_ids: set[str] = set()
        artifact_ids: set[str] = set()
        accepted_expectation = RevAcceptanceExpectation.from_mapping(
            normalized_oracle["accepted"]
        )
        control_expectations = [
            RevAcceptanceExpectation.from_mapping(
                item["expectation"]
            )
            for item in normalized_oracle["controls"]
        ]
        for index, observation in enumerate(
            acceptance["observations"]
        ):
            if (
                observation["run_id"] in run_ids
                or observation["receipt_id"] in receipt_ids
                or observation["stdout_artifact_id"] in artifact_ids
                or observation["stderr_artifact_id"] in artifact_ids
                or observation["stdout_artifact_id"]
                == observation["stderr_artifact_id"]
            ):
                independently_derived_reasons.append("identity_reused")
            run_ids.add(observation["run_id"])
            receipt_ids.add(observation["receipt_id"])
            artifact_ids.update(
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
                independently_derived_reasons.append(
                    f"attempt_{index + 1}_transport_incomplete"
                )
            expectation = (
                accepted_expectation
                if index < 3
                else control_expectations[index - 3]
            )
            if not expectation.matches(observation):
                independently_derived_reasons.append(
                    f"attempt_{index + 1}_oracle_mismatch"
                )
        independently_derived_reasons = list(
            dict.fromkeys(independently_derived_reasons)
        )
        if acceptance["reason_codes"] != independently_derived_reasons:
            raise RevRuntimeProofError(
                "runtime_evaluation_acceptance_invalid"
            )
        if sandbox_reused:
            expected_reasons.append("sandbox_identity_reused")
        expected_reasons = list(dict.fromkeys(expected_reasons))
        if value["reason_codes"] != expected_reasons:
            raise RevRuntimeProofError(
                "runtime_evaluation_reason_invalid"
            )
        observations = acceptance["observations"]
        if any(
            item["input_sha256"] != accepted["sha256"]
            or item["input_size_bytes"] != accepted["size_bytes"]
            for item in observations[:3]
        ) or any(
            item["input_sha256"] == accepted["sha256"]
            and item["input_size_bytes"] == accepted["size_bytes"]
            for item in observations[3:]
        ):
            raise RevRuntimeProofError(
                "runtime_evaluation_input_invalid"
            )
        canonical_json_bytes(value)
    except (
        RevAcceptanceContractError,
        RevRuntimeV1Error,
        SafeFileError,
    ) as error:
        raise RevRuntimeProofError(
            "runtime_evaluation_invalid"
        ) from error
    return value


def _public_runtime_evaluation(
    private_evaluation: Mapping[str, object],
    *,
    private_sha256: str,
    private_size_bytes: int,
) -> dict[str, object]:
    """Project only non-secret commitments into canonical/public state."""

    accepted = private_evaluation["accepted_input"]
    runtime_spec = private_evaluation["runtime_spec"]
    acceptance = private_evaluation["acceptance_evaluation"]
    records = private_evaluation["records"]
    expected_oracle = private_evaluation["expected_oracle"]
    assert isinstance(accepted, Mapping)
    assert isinstance(runtime_spec, Mapping)
    assert isinstance(acceptance, Mapping)
    assert isinstance(records, list)
    assert isinstance(expected_oracle, Mapping)
    projection = {
        "accepted_input": {
            "sha256": accepted["sha256"],
            "size_bytes": accepted["size_bytes"],
        },
        "authorities": copy.deepcopy(private_evaluation["authorities"]),
        "expected_oracle": {
            "sha256": private_evaluation["expected_oracle_sha256"],
            "size_bytes": len(canonical_json_bytes(dict(expected_oracle))),
        },
        "image_digest": private_evaluation["image_digest"],
        "passed": private_evaluation["passed"],
        "plan_sha256": acceptance["plan_sha256"],
        "private_evaluation": {
            "sha256": private_sha256,
            "size_bytes": private_size_bytes,
        },
        "proof_scope_fingerprint": private_evaluation[
            "proof_scope_fingerprint"
        ],
        "protocol": REV_RUNTIME_PROOF_PROTOCOL,
        "reason_codes": copy.deepcopy(private_evaluation["reason_codes"]),
        "record_count": len(records),
        "records_sha256": sha256(canonical_json_bytes(records)),
        "runner_attestation": copy.deepcopy(
            private_evaluation["runner_attestation"]
        ),
        "runtime_spec": {
            "argv_sha256": runtime_spec["argv_sha256"],
            "format": runtime_spec["format"],
            "runtime": runtime_spec["runtime"],
            "sha256": runtime_spec["sha256"],
            "size_bytes": runtime_spec["size_bytes"],
        },
        "schema_version": REV_RUNTIME_PROOF_SCHEMA_VERSION,
        "source_closure_sha256": private_evaluation[
            "source_closure_sha256"
        ],
        "source_manifest_sha256": private_evaluation[
            "source_manifest_sha256"
        ],
    }
    if len(canonical_json_bytes(projection)) > REV_ACCEPTANCE_MAX_EVIDENCE_BYTES:
        raise RevRuntimeProofError("runtime_public_evaluation_too_large")
    return projection


def validate_rev_runtime_proof_evaluation(
    value: object,
) -> dict[str, object]:
    """Strictly validate the commitment-only public runtime projection."""

    expected_keys = {
        "accepted_input",
        "authorities",
        "expected_oracle",
        "image_digest",
        "passed",
        "plan_sha256",
        "private_evaluation",
        "proof_scope_fingerprint",
        "protocol",
        "reason_codes",
        "record_count",
        "records_sha256",
        "runner_attestation",
        "runtime_spec",
        "schema_version",
        "source_closure_sha256",
        "source_manifest_sha256",
    }
    if type(value) is not dict or set(value) != expected_keys:
        raise RevRuntimeProofError("runtime_public_evaluation_schema_invalid")
    accepted = value["accepted_input"]
    oracle = value["expected_oracle"]
    private = value["private_evaluation"]
    runtime_spec = value["runtime_spec"]
    digest_fields = (
        "plan_sha256",
        "proof_scope_fingerprint",
        "records_sha256",
        "source_closure_sha256",
        "source_manifest_sha256",
    )
    if (
        value["protocol"] != REV_RUNTIME_PROOF_PROTOCOL
        or value["schema_version"] != REV_RUNTIME_PROOF_SCHEMA_VERSION
        or value["authorities"] != _AUTHORITIES
        or value["runner_attestation"] != REV_RUNTIME_EXEC_ATTESTATION
        or type(value["image_digest"]) is not str
        or _DIGEST_PIN.fullmatch(value["image_digest"]) is None
        or type(value["passed"]) is not bool
        or type(value["reason_codes"]) is not list
        or value["passed"] is not (not value["reason_codes"])
        or any(
            type(code) is not str or not code
            for code in value["reason_codes"]
        )
        or len(set(value["reason_codes"])) != len(value["reason_codes"])
        or type(value["record_count"]) is not int
        or value["record_count"] != 6
        or any(
            type(value[field]) is not str
            or _SHA256.fullmatch(value[field]) is None
            for field in digest_fields
        )
        or type(accepted) is not dict
        or set(accepted) != {"sha256", "size_bytes"}
        or type(accepted["sha256"]) is not str
        or _SHA256.fullmatch(accepted["sha256"]) is None
        or type(accepted["size_bytes"]) is not int
        or not 0 <= accepted["size_bytes"] <= REV_ACCEPTANCE_MAX_INPUT_BYTES
        or type(oracle) is not dict
        or set(oracle) != {"sha256", "size_bytes"}
        or type(oracle["sha256"]) is not str
        or _SHA256.fullmatch(oracle["sha256"]) is None
        or type(oracle["size_bytes"]) is not int
        or not 1 <= oracle["size_bytes"] <= REV_ACCEPTANCE_MAX_SPEC_BYTES
        or type(private) is not dict
        or set(private) != {"sha256", "size_bytes"}
        or type(private["sha256"]) is not str
        or _SHA256.fullmatch(private["sha256"]) is None
        or type(private["size_bytes"]) is not int
        or not 1
        <= private["size_bytes"]
        <= REV_ACCEPTANCE_MAX_EVIDENCE_BYTES
        or type(runtime_spec) is not dict
        or set(runtime_spec)
        != {
            "argv_sha256",
            "format",
            "runtime",
            "sha256",
            "size_bytes",
        }
        or type(runtime_spec["argv_sha256"]) is not str
        or _SHA256.fullmatch(runtime_spec["argv_sha256"]) is None
        or type(runtime_spec["sha256"]) is not str
        or _SHA256.fullmatch(runtime_spec["sha256"]) is None
        or runtime_spec["format"] not in REV_RUNTIME_V1_FORMATS
        or runtime_spec["runtime"] not in REV_RUNTIME_V1_RUNTIMES
        or type(runtime_spec["size_bytes"]) is not int
        or not 1
        <= runtime_spec["size_bytes"]
        <= REV_RUNTIME_V1_MAX_DOCUMENT_BYTES
    ):
        raise RevRuntimeProofError("runtime_public_evaluation_invalid")
    try:
        canonical_json_bytes(value)
    except (TypeError, ValueError) as error:
        raise RevRuntimeProofError(
            "runtime_public_evaluation_invalid"
        ) from error
    return value


def rev_runtime_proof_state_errors(
    state: ChallengeState,
) -> tuple[str, ...]:
    """Validate the public commitment plus its hidden artifact/run graph."""

    errors: list[str] = []
    artifacts = {item.id: item for item in state.artifacts}
    runs = {item.id: item for item in state.runs}
    evidence_keys = {
        "base_revision",
        "configuration_epoch",
        "evaluation",
        "experiment_id",
        "protocol",
        "schema_version",
    }
    for experiment in state.experiments:
        if (
            not isinstance(experiment.result, Mapping)
            or REV_RUNTIME_PROOF_RESULT_KEY not in experiment.result
        ):
            continue
        label = f"Rev runtime proof {experiment.id}"
        evidence = experiment.result.get(REV_RUNTIME_PROOF_RESULT_KEY)
        if type(evidence) is not dict or set(evidence) != evidence_keys:
            errors.append(f"{label} public evidence schema is invalid")
            continue
        try:
            evaluation = validate_rev_runtime_proof_evaluation(
                evidence["evaluation"]
            )
        except (RevRuntimeProofError, TypeError, ValueError) as error:
            errors.append(f"{label} public evaluation is invalid: {error}")
            continue
        if (
            evidence["experiment_id"] != experiment.id
            or evidence["protocol"] != REV_RUNTIME_PROOF_PROTOCOL
            or evidence["schema_version"]
            != REV_RUNTIME_PROOF_SCHEMA_VERSION
            or type(evidence["base_revision"]) is not int
            or type(evidence["configuration_epoch"]) is not int
            or evidence["configuration_epoch"] > state.configuration_epoch
            or experiment.kind is not ExperimentKind.PROBE
            or experiment.status
            is not (
                ExperimentStatus.COMPLETED
                if evaluation["passed"]
                else ExperimentStatus.FAILED
            )
            or experiment.extra.get("engine_executor")
            != REV_RUNTIME_PROOF_EXECUTOR
            or experiment.extra.get("context_visibility")
            != "commitment_only"
            or experiment.extra.get("protocol")
            != REV_RUNTIME_PROOF_PROTOCOL
            or set(experiment.extra)
            != {
                "context_visibility",
                "engine_executor",
                "protocol",
            }
            or experiment.hypothesis_ids
            or experiment.evidence_fact_ids
            or experiment.evidence_receipt_ids
            or experiment.evidence_run_ids
            or experiment.artifact_ids
        ):
            errors.append(f"{label} public aggregate binding is inconsistent")
            continue

        owned_artifacts = [
            item
            for item in artifacts.values()
            if item.extra.get("engine_executor")
            == REV_RUNTIME_PROOF_EXECUTOR
            and item.extra.get("experiment_id") == experiment.id
        ]
        by_kind: dict[str, list[ArtifactReference]] = {}
        for artifact in owned_artifacts:
            kind = artifact.extra.get("kind")
            if isinstance(kind, str):
                by_kind.setdefault(kind, []).append(artifact)
        spec_items = by_kind.get("rev_runtime_spec", [])
        input_items = by_kind.get("rev_runtime_accepted_input", [])
        evaluation_items = by_kind.get("rev_runtime_evaluation", [])
        streams = by_kind.get("rev_runtime_stream", [])
        expected_root = f"artifacts/rev-runtime-proof/{experiment.id}"
        if (
            len(owned_artifacts) != 15
            or len(spec_items) != 1
            or len(input_items) != 1
            or len(evaluation_items) != 1
            or len(streams) != 12
            or any(
                artifact.extra.get("context_visibility")
                != "engine_private"
                for artifact in owned_artifacts
            )
        ):
            errors.append(f"{label} hidden artifact topology is incomplete")
            continue
        spec_artifact = spec_items[0]
        input_artifact = input_items[0]
        evaluation_artifact = evaluation_items[0]
        artifact_extra_keys = {
            "context_visibility",
            "engine_executor",
            "experiment_id",
            "kind",
            "protocol",
        }
        if (
            spec_artifact.path != f"{expected_root}/runtime-spec.json"
            or input_artifact.path != f"{expected_root}/accepted-input.bin"
            or evaluation_artifact.path != f"{expected_root}/evaluation.json"
            or spec_artifact.source_run_id is not None
            or input_artifact.source_run_id is not None
            or spec_artifact.sha256 != evaluation["runtime_spec"]["sha256"]
            or spec_artifact.size
            != evaluation["runtime_spec"]["size_bytes"]
            or input_artifact.sha256
            != evaluation["accepted_input"]["sha256"]
            or input_artifact.size
            != evaluation["accepted_input"]["size_bytes"]
            or evaluation_artifact.sha256
            != evaluation["private_evaluation"]["sha256"]
            or evaluation_artifact.size
            != evaluation["private_evaluation"]["size_bytes"]
            or spec_artifact.media_type != "application/json"
            or input_artifact.media_type != "application/octet-stream"
            or evaluation_artifact.media_type != "application/json"
            or set(spec_artifact.extra) != artifact_extra_keys
            or set(input_artifact.extra) != artifact_extra_keys
            or set(evaluation_artifact.extra)
            != artifact_extra_keys | {"evaluation_sha256"}
            or evaluation_artifact.extra.get("evaluation_sha256")
            != evaluation_artifact.sha256
        ):
            errors.append(f"{label} hidden artifact binding is invalid")
            continue

        proof_runs = [
            run
            for run in runs.values()
            if run.extra.get("engine_executor")
            == REV_RUNTIME_PROOF_EXECUTOR
            and run.extra.get("parent_experiment_id") == experiment.id
        ]
        expected_mutations = {
            1: "accepted-repeat-1",
            2: "accepted-repeat-2",
            3: "accepted-repeat-3",
            4: "xor-first-01",
            5: "xor-last-80",
            6: "truncate-last",
        }
        run_extra_keys = {
            "context_visibility",
            "engine_executor",
            "experiment_id",
            "parent_experiment_id",
            "request_sha256",
            "request_size_bytes",
            "result_sha256",
            "result_size_bytes",
            "rev_runtime_proof",
            "validation_sha256",
            "validation_size_bytes",
        }
        terminal_statuses = {
            RunStatus.COMPLETED,
            RunStatus.FAILED,
            RunStatus.TIMED_OUT,
        }
        ordinals: set[int] = set()
        proof_run_ids: set[str] = set()
        runs_by_ordinal: dict[int, RunReference] = {}
        for run in proof_runs:
            marker = run.extra.get("rev_runtime_proof")
            ordinal = (
                marker.get("ordinal")
                if isinstance(marker, Mapping)
                else None
            )
            if (
                type(ordinal) is not int
                or not 1 <= ordinal <= 6
                or ordinal in ordinals
                or run.base_revision != evidence["base_revision"]
                or run.configuration_epoch
                != evidence["configuration_epoch"]
                or run.role != "rev_runtime_proof"
                or run.origin is not RunOrigin.OPERATOR_TOOL
                or run.status not in terminal_statuses
                or (
                    evaluation["passed"]
                    and run.status is not RunStatus.COMPLETED
                )
                or run.request_path != f"runs/{run.id}/request.json"
                or run.result_path != f"runs/{run.id}/result.json"
                or run.validation_path
                != f"runs/{run.id}/validation.json"
                or set(run.extra) != run_extra_keys
                or run.extra.get("context_visibility")
                != "engine_private"
                or run.extra.get("experiment_id") != experiment.id
                or run.extra.get("parent_experiment_id")
                != experiment.id
                or type(marker) is not dict
                or set(marker)
                != {"mutation_id", "ordinal", "protocol"}
                or marker.get("protocol") != REV_RUNTIME_PROOF_PROTOCOL
                or marker.get("mutation_id")
                != expected_mutations.get(ordinal)
                or any(
                    type(run.extra.get(f"{prefix}_sha256")) is not str
                    or _SHA256.fullmatch(
                        str(run.extra.get(f"{prefix}_sha256"))
                    )
                    is None
                    or type(run.extra.get(f"{prefix}_size_bytes"))
                    is not int
                    or not 1
                    <= int(run.extra.get(f"{prefix}_size_bytes"))
                    <= REV_ACCEPTANCE_MAX_EVIDENCE_BYTES
                    for prefix in ("request", "result", "validation")
                )
            ):
                errors.append(f"{label} hidden run binding is invalid")
                break
            ordinals.add(ordinal)
            proof_run_ids.add(run.id)
            runs_by_ordinal[ordinal] = run
        else:
            stream_keys = {
                (item.extra.get("ordinal"), item.extra.get("stream"))
                for item in streams
            }
            if (
                len(proof_runs) != 6
                or ordinals != set(range(1, 7))
                or stream_keys
                != {
                    (ordinal, stream)
                    for ordinal in range(1, 7)
                    for stream in ("stdout", "stderr")
                }
                or any(
                    set(stream.extra)
                    != artifact_extra_keys | {"ordinal", "stream"}
                    or stream.extra.get("protocol")
                    != REV_RUNTIME_PROOF_PROTOCOL
                    or stream.extra.get("kind")
                    != "rev_runtime_stream"
                    or stream.media_type != "application/octet-stream"
                    or type(stream.size) is not int
                    or not 0 <= stream.size <= REV_ACCEPTANCE_MAX_STREAM_BYTES
                    or type(stream.sha256) is not str
                    or _SHA256.fullmatch(stream.sha256) is None
                    or type(stream.extra.get("ordinal")) is not int
                    or stream.extra.get("stream") not in {"stdout", "stderr"}
                    or stream.source_run_id
                    != runs_by_ordinal[
                        int(stream.extra.get("ordinal"))
                    ].id
                    or stream.path
                    != (
                        f"{expected_root}/streams/"
                        f"{stream.source_run_id}/"
                        f"{stream.extra.get('stream')}.bin"
                    )
                    for stream in streams
                )
                or evaluation_artifact.source_run_id
                != runs_by_ordinal[6].id
                or any(
                    receipt.run_id in proof_run_ids
                    for receipt in state.receipts
                )
            ):
                errors.append(f"{label} hidden run topology is incomplete")
    return tuple(errors)


def validate_rev_runtime_proof_state_graph(
    state: ChallengeState,
) -> None:
    errors = rev_runtime_proof_state_errors(state)
    if errors:
        raise RevRuntimeProofError("; ".join(errors))


def prove_rev_runtime_accepted_input(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    runtime_spec_locator: str,
    accepted_input_path: Path,
    expected_oracle: Mapping[str, object],
    timeout_seconds: int = 300,
    _session_owned: bool = False,
) -> tuple[ChallengeState, dict[str, object]]:
    """Run one exact Rev runtime in three positives and three controls."""

    try:
        normalized_spec_locator = normalize_locator(runtime_spec_locator)
    except SafeFileError as error:
        raise RevRuntimeProofError("runtime_request_invalid") from error
    if (
        not isinstance(accepted_input_path, Path)
        or type(timeout_seconds) is not int
        or not 1
        <= timeout_seconds
        <= REV_RUNTIME_PROOF_MAX_TIMEOUT_SECONDS
        or not isinstance(expected_oracle, Mapping)
    ):
        raise RevRuntimeProofError("runtime_request_invalid")
    if _session_owned:
        # Managed callers require a dedicated engine preissue handoff.  A
        # challenge-workspace locator is never an acceptable substitute.
        raise RevRuntimeProofError(
            "runtime_managed_private_input_preissue_required"
        )
    try:
        normalized_oracle = validate_rev_acceptance_expected_oracle(
            copy.deepcopy(dict(expected_oracle))
        )
    except (RevAcceptanceContractError, TypeError, ValueError) as error:
        raise RevRuntimeProofError("runtime_expected_oracle_invalid") from error

    paths = engine.store.challenge_paths(identity)
    lock: ChallengeLock | None = None
    pending_artifacts: list[ArtifactReference] = []
    pending_run_ids: list[str] = []
    committed_state = False
    try:
        lock = ChallengeLock(
            paths.runtime / "session.lock",
            timeout=0,
        ).acquire()
    except LockTimeout as error:
        raise RevRuntimeProofError("runtime_session_busy") from error

    try:
        engine._recover_session_boundary(identity)
        state = engine.refresh_ingest(identity)
        engine._remaining_budget_seconds(state)
        image_digest = engine.config.runtime.image_digest
        if (
            state.schema_version < STATE_SCHEMA_VERSION
            or get_adapter(state.category).name != "reversing"
            or state.status
            in {
                ChallengeStatus.NEW,
                ChallengeStatus.PAUSED,
                ChallengeStatus.SOLVED,
                ChallengeStatus.ABANDONED,
            }
            or state.primary_target_id is not None
            or type(image_digest) is not str
            or _DIGEST_PIN.fullmatch(image_digest) is None
        ):
            raise RevRuntimeProofError("runtime_preflight_rejected")
        before_status = state.status
        before_candidate_ids = tuple(item.id for item in state.candidates)
        before_submission_ids = tuple(item.id for item in state.submissions)
        before_target_ids = tuple(item.id for item in state.targets)
        base_revision = state.revision
        configuration_epoch = state.configuration_epoch
        source_manifest_sha256 = state.metadata.get(
            "source_manifest_sha256"
        )
        if (
            type(source_manifest_sha256) is not str
            or _SHA256.fullmatch(source_manifest_sha256) is None
        ):
            raise RevRuntimeProofError("runtime_source_binding_invalid")
        initial_attestation = _probe_runtime_capability(
            engine,
            image_digest,
        )

        experiment_id = _new_id("E-rev-runtime")
        artifact_root = ensure_private_directory(
            paths.artifacts / "rev-runtime-proof" / experiment_id
        )
        source_client = engine.sandbox(
            state,
            network_policy_override=NetworkPolicy.deny_all(),
        )
        if (
            type(source_client.scope_fingerprint) is not str
            or _SHA256.fullmatch(source_client.scope_fingerprint) is None
        ):
            raise RevRuntimeProofError("runtime_workspace_scope_invalid")

        spec_artifact_id = _new_id("A-rev-runtime-spec")
        spec_destination = artifact_root / "runtime-spec.json"
        pending_artifacts.append(
            ArtifactReference(
                id=spec_artifact_id,
                path=spec_destination.relative_to(paths.root).as_posix(),
                sha256="0" * 64,
            )
        )
        spec_snapshot = _snapshot_workspace(
            engine,
            state,
            source_client,
            locator=normalized_spec_locator,
            destination=spec_destination,
            artifact_id=spec_artifact_id,
            maximum_bytes=REV_RUNTIME_V1_MAX_DOCUMENT_BYTES,
        )
        try:
            spec_payload = read_bounded_regular(
                paths.root,
                spec_snapshot.path,
                maximum_bytes=REV_RUNTIME_V1_MAX_DOCUMENT_BYTES,
                expected_sha256=spec_snapshot.sha256,
                expected_size=spec_snapshot.size_bytes,
            )
            runtime_spec = RevRuntimeV1Spec.from_mapping(
                strict_json_loads(
                    spec_payload,
                    max_bytes=REV_RUNTIME_V1_MAX_DOCUMENT_BYTES,
                )
            )
            if spec_payload != runtime_spec.canonical_bytes:
                raise RevRuntimeV1Error("runtime_spec_not_canonical")
            runtime_spec.require_supported()
        except RevRuntimeV1Error as error:
            if error.code == "runtime_unsupported_dex_apk":
                raise RevRuntimeProofError(error.code) from error
            raise RevRuntimeProofError("runtime_spec_invalid") from error
        except (
            OSError,
            SafeFileError,
            StrictJSONError,
            TypeError,
            ValueError,
        ) as error:
            raise RevRuntimeProofError("runtime_spec_invalid") from error

        input_artifact_id = _new_id("A-rev-runtime-input")
        input_destination = artifact_root / "accepted-input.bin"
        pending_artifacts.append(
            ArtifactReference(
                id=input_artifact_id,
                path=input_destination.relative_to(paths.root).as_posix(),
                sha256="0" * 64,
            )
        )
        input_snapshot, accepted_input = _snapshot_operator_input(
            engine,
            state,
            accepted_input_path=accepted_input_path,
            destination=input_destination,
            artifact_id=input_artifact_id,
        )
        try:
            if _accepted_input_disclosed(runtime_spec, accepted_input):
                raise RevRuntimeProofError(
                    "runtime_input_disclosed_in_spec"
                )
            plan = build_rev_acceptance_plan(accepted_input)
            operator_spec = RevAcceptanceOperatorSpec.from_mapping(
                {
                    "accepted": normalized_oracle["accepted"],
                    "accepted_input_locator": (
                        "engine-private/accepted-input.bin"
                    ),
                    "controls": normalized_oracle["controls"],
                    "protocol": REV_ACCEPTANCE_OPERATOR_SPEC_PROTOCOL,
                    "schema_version": REV_ACCEPTANCE_SCHEMA_VERSION,
                    "source_locator": runtime_spec.source.path,
                }
            )
        except RevRuntimeProofError:
            raise
        except (
            OSError,
            SafeFileError,
            RevAcceptanceContractError,
            TypeError,
            ValueError,
        ) as error:
            raise RevRuntimeProofError("runtime_input_invalid") from error

        _require_incoming_current(
            engine,
            state,
            runtime_spec,
            expected_manifest_sha256=source_manifest_sha256,
        )
        spec_artifact = ArtifactReference(
            id=spec_snapshot.artifact_id,
            path=spec_snapshot.path,
            sha256=spec_snapshot.sha256,
            size=spec_snapshot.size_bytes,
            media_type="application/json",
            extra=_artifact_extra(
                experiment_id=experiment_id,
                kind="rev_runtime_spec",
            ),
        )
        input_artifact = ArtifactReference(
            id=input_snapshot.artifact_id,
            path=input_snapshot.path,
            sha256=input_snapshot.sha256,
            size=input_snapshot.size_bytes,
            media_type="application/octet-stream",
            extra=_artifact_extra(
                experiment_id=experiment_id,
                kind="rev_runtime_accepted_input",
            ),
        )
        all_artifacts: list[ArtifactReference] = [
            spec_artifact,
            input_artifact,
        ]
        run_records: list[_RunRecord] = []
        observations: list[dict[str, object]] = []
        records: list[dict[str, object]] = []
        additional_reason_codes: list[str] = []
        command_timeout = engine._budget_command_timeout(
            state,
            timeout_seconds,
        )
        request_resources = tool_profile("standard", network=False)
        sandbox_run_ids: set[str] = set()
        result_locators: set[str] = set()

        snapshot_parent = ensure_private_directory(
            paths.runtime / "rev-runtime-proof-snapshots"
        )
        proof_parent = ensure_private_directory(
            paths.runtime / "rev-runtime-proof-workspaces"
        )
        with (
            tempfile.TemporaryDirectory(
                prefix=f".{experiment_id}-",
                dir=snapshot_parent,
            ) as snapshot_name,
            tempfile.TemporaryDirectory(
                prefix=f".{experiment_id}-",
                dir=proof_parent,
            ) as proof_name,
        ):
            snapshot_base = Path(snapshot_name)
            challenge_root = ensure_private_directory(
                snapshot_base / "challenge"
            )
            proof_workspace = ensure_private_directory(Path(proof_name))
            try:
                _build_source_snapshot(
                    engine,
                    state,
                    runtime_spec,
                    challenge_root,
                )
                atomic_write_bytes(
                    proof_workspace / "runtime-spec.json",
                    runtime_spec.canonical_bytes,
                    mode=0o400,
                )
                proof_client = engine.sandbox(
                    state,
                    workspace_override=proof_workspace,
                    challenge_dir_override=challenge_root,
                    network_policy_override=NetworkPolicy.deny_all(),
                )
                proof_scope = proof_client.scope_fingerprint
                if (
                    type(proof_scope) is not str
                    or _SHA256.fullmatch(proof_scope) is None
                ):
                    raise RevRuntimeProofError(
                        "runtime_proof_scope_invalid"
                    )
                inputs_directory = ensure_private_directory(
                    proof_workspace / "inputs"
                )
                for planned in plan:
                    _require_incoming_current(
                        engine,
                        state,
                        runtime_spec,
                        expected_manifest_sha256=source_manifest_sha256,
                    )
                    _verify_source_snapshot(challenge_root, runtime_spec)
                    _require_workspace_current(
                        source_client,
                        spec_snapshot,
                    )
                    if (
                        engine.config.runtime.image_digest != image_digest
                        or proof_client.scope_fingerprint != proof_scope
                    ):
                        raise RevRuntimeProofError(
                            "runtime_external_binding_changed"
                        )
                    read_bounded_regular(
                        paths.root,
                        spec_snapshot.path,
                        maximum_bytes=REV_RUNTIME_V1_MAX_DOCUMENT_BYTES,
                        expected_sha256=spec_snapshot.sha256,
                        expected_size=spec_snapshot.size_bytes,
                    )
                    read_bounded_regular(
                        paths.root,
                        input_snapshot.path,
                        maximum_bytes=REV_ACCEPTANCE_MAX_INPUT_BYTES,
                        expected_sha256=input_snapshot.sha256,
                        expected_size=input_snapshot.size_bytes,
                    )

                    attempt_path = (
                        inputs_directory
                        / f"attempt-{planned.ordinal:02d}.bin"
                    )
                    atomic_write_bytes(
                        attempt_path,
                        planned.payload,
                        mode=0o400,
                    )
                    proof_inputs = (
                        ProofInput(
                            source_locator="runtime-spec.json",
                            destination_locator="oracle/runtime-spec.json",
                            sha256=runtime_spec.sha256,
                            size_bytes=len(runtime_spec.canonical_bytes),
                        ),
                        ProofInput(
                            source_locator=attempt_path.relative_to(
                                proof_workspace
                            ).as_posix(),
                            destination_locator=(
                                "oracle/accepted-input.bin"
                            ),
                            sha256=planned.input_sha256,
                            size_bytes=len(planned.payload),
                        ),
                    )
                    run_id = _new_id("R-rev-runtime")
                    receipt_id = _new_id("RCPT-rev-runtime")
                    pending_run_ids.append(run_id)
                    request_payload = {
                        "configuration_epoch": configuration_epoch,
                        "experiment_id": experiment_id,
                        "image_digest": image_digest,
                        "input_sha256": planned.input_sha256,
                        "input_size_bytes": len(planned.payload),
                        "kind": "rev_runtime_proof",
                        "mutation_id": planned.mutation_id,
                        "network": "none",
                        "ordinal": planned.ordinal,
                        "phase": planned.phase,
                        "protocol": REV_RUNTIME_PROOF_PROTOCOL,
                        "resource_request": request_resources.as_dict(),
                        "runner_sha256": REV_RUNTIME_EXEC_SHA256,
                        "runtime_spec_sha256": runtime_spec.sha256,
                        "source_closure_sha256": (
                            _source_closure_sha256(runtime_spec)
                        ),
                        "source_manifest_sha256": (
                            source_manifest_sha256
                        ),
                    }
                    run_paths = engine.store.create_run(
                        identity,
                        run_id=run_id,
                        request=request_payload,
                        base_revision=base_revision,
                    )
                    lease = engine.lease_broker.acquire(
                        request_resources,
                        timeout=engine._budget_wait_timeout(
                            state,
                            engine.config.resources.lease_wait_timeout_s,
                        ),
                        owner=(
                            f"{identity.key}:rev-runtime:"
                            f"{experiment_id}:{planned.ordinal}"
                        ),
                    )
                    if lease is None:
                        raise RevRuntimeProofError(
                            "runtime_resource_wait_timeout"
                        )
                    try:
                        result = proof_client.run_clean_proof(
                            CommandSpec.create(
                                REV_RUNTIME_EXEC_ARGV,
                                timeout_seconds=command_timeout,
                                summary_bytes=0,
                                network_target=None,
                                resource_request=request_resources,
                            ),
                            proof_inputs=proof_inputs,
                        )
                    finally:
                        lease.release()
                    if (
                        proof_client.scope_fingerprint != proof_scope
                        or type(result.run_id) is not str
                        or not result.run_id
                    ):
                        raise RevRuntimeProofError(
                            "runtime_proof_scope_changed"
                        )
                    stdout_locator = _normalized_result_locator(
                        result.stdout_path
                    )
                    stderr_locator = _normalized_result_locator(
                        result.stderr_path
                    )
                    reused_identity = (
                        result.run_id in sandbox_run_ids
                        or stdout_locator == stderr_locator
                        or stdout_locator in result_locators
                        or stderr_locator in result_locators
                    )
                    sandbox_run_ids.add(result.run_id)
                    result_locators.update(
                        (stdout_locator, stderr_locator)
                    )
                    if reused_identity:
                        additional_reason_codes.append(
                            "sandbox_identity_reused"
                        )

                    stream_artifacts: list[ArtifactReference] = []
                    for stream_name, locator in (
                        ("stdout", stdout_locator),
                        ("stderr", stderr_locator),
                    ):
                        artifact_id = _new_id(
                            f"A-rev-runtime-{stream_name}"
                        )
                        destination = (
                            artifact_root
                            / "streams"
                            / run_id
                            / f"{stream_name}.bin"
                        )
                        pending_artifacts.append(
                            ArtifactReference(
                                id=artifact_id,
                                path=destination.relative_to(
                                    paths.root
                                ).as_posix(),
                                sha256="0" * 64,
                                source_run_id=run_id,
                            )
                        )
                        ensure_private_directory(destination.parent)
                        immutable = _snapshot_proof_stream(
                            proof_client,
                            workspace_root=proof_workspace,
                            locator=locator,
                            destination=destination,
                        )
                        if (
                            immutable.size_bytes
                            > REV_ACCEPTANCE_MAX_STREAM_BYTES
                        ):
                            raise RevRuntimeProofError(
                                "runtime_stream_too_large"
                            )
                        stream_artifacts.append(
                            ArtifactReference(
                                id=artifact_id,
                                path=immutable.path.relative_to(
                                    paths.root
                                ).as_posix(),
                                sha256=immutable.sha256,
                                source_run_id=run_id,
                                size=immutable.size_bytes,
                                media_type="application/octet-stream",
                                extra=_artifact_extra(
                                    experiment_id=experiment_id,
                                    kind="rev_runtime_stream",
                                    ordinal=planned.ordinal,
                                    stream=stream_name,
                                ),
                            )
                        )
                    stdout_artifact, stderr_artifact = stream_artifacts
                    capture_complete = (
                        _complete_transport(result)
                        and _stream_capture_matches(
                            result,
                            stream="stdout",
                            size_bytes=stdout_artifact.size or 0,
                        )
                        and _stream_capture_matches(
                            result,
                            stream="stderr",
                            size_bytes=stderr_artifact.size or 0,
                        )
                    )
                    observation = {
                        "capture_complete": capture_complete,
                        "clean_workspace": True,
                        "exit_code": (
                            result.exit_code
                            if type(result.exit_code) is int
                            and 0 <= result.exit_code <= 255
                            else 255
                        ),
                        "input_sha256": planned.input_sha256,
                        "input_size_bytes": len(planned.payload),
                        "mutation_id": planned.mutation_id,
                        "network": "none",
                        "ordinal": planned.ordinal,
                        "phase": planned.phase,
                        "receipt_id": receipt_id,
                        "run_id": run_id,
                        "stderr_artifact_id": stderr_artifact.id,
                        "stderr_sha256": stderr_artifact.sha256,
                        "stderr_size_bytes": stderr_artifact.size,
                        "stdout_artifact_id": stdout_artifact.id,
                        "stdout_sha256": stdout_artifact.sha256,
                        "stdout_size_bytes": stdout_artifact.size,
                        "timed_out": result.timed_out is True,
                    }
                    durable_result = engine.store.write_run_result(
                        identity,
                        run_id,
                        {
                            "artifacts": [
                                item.to_dict()
                                for item in stream_artifacts
                            ],
                            "rev_runtime_observation": observation,
                            "status": "completed",
                        },
                    )
                    validation_path = engine.store.write_run_validation(
                        identity,
                        run_id,
                        {
                            "rev_runtime_observation": observation,
                            "status": (
                                "valid_transport"
                                if capture_complete
                                else "invalid_transport"
                            ),
                        },
                    )
                    request_sha256, request_size = _file_binding(
                        paths.root,
                        run_paths.request,
                        maximum_bytes=REV_ACCEPTANCE_MAX_EVIDENCE_BYTES,
                    )
                    result_sha256, result_size = _file_binding(
                        paths.root,
                        durable_result,
                        maximum_bytes=REV_ACCEPTANCE_MAX_EVIDENCE_BYTES,
                    )
                    validation_sha256, validation_size = _file_binding(
                        paths.root,
                        validation_path,
                        maximum_bytes=REV_ACCEPTANCE_MAX_EVIDENCE_BYTES,
                    )
                    record = {
                        "observation": copy.deepcopy(observation),
                        "request_path": run_paths.request.relative_to(
                            paths.root
                        ).as_posix(),
                        "request_sha256": request_sha256,
                        "request_size_bytes": request_size,
                        "result_path": durable_result.relative_to(
                            paths.root
                        ).as_posix(),
                        "result_sha256": result_sha256,
                        "result_size_bytes": result_size,
                        "sandbox_run_id": result.run_id,
                        "scope_fingerprint": proof_scope,
                        "stderr_locator": stderr_locator,
                        "stdout_locator": stdout_locator,
                        "validation_path": validation_path.relative_to(
                            paths.root
                        ).as_posix(),
                        "validation_sha256": validation_sha256,
                        "validation_size_bytes": validation_size,
                    }
                    marker = {
                        "mutation_id": planned.mutation_id,
                        "ordinal": planned.ordinal,
                        "protocol": REV_RUNTIME_PROOF_PROTOCOL,
                    }
                    run = RunReference(
                        id=run_id,
                        base_revision=base_revision,
                        status=(
                            RunStatus.COMPLETED
                            if capture_complete
                            else (
                                RunStatus.TIMED_OUT
                                if result.timed_out is True
                                else RunStatus.FAILED
                            )
                        ),
                        request_path=record["request_path"],
                        result_path=record["result_path"],
                        validation_path=record["validation_path"],
                        role="rev_runtime_proof",
                        origin=(
                            RunOrigin.MANAGED_TOOL
                            if _session_owned
                            else RunOrigin.OPERATOR_TOOL
                        ),
                        configuration_epoch=configuration_epoch,
                        extra={
                            "context_visibility": "engine_private",
                            "engine_executor": REV_RUNTIME_PROOF_EXECUTOR,
                            "experiment_id": experiment_id,
                            "parent_experiment_id": experiment_id,
                            "request_sha256": request_sha256,
                            "request_size_bytes": request_size,
                            "result_sha256": result_sha256,
                            "result_size_bytes": result_size,
                            "rev_runtime_proof": marker,
                            "validation_sha256": validation_sha256,
                            "validation_size_bytes": validation_size,
                        },
                    )
                    run_records.append(
                        _RunRecord(
                            run=run,
                            artifacts=(
                                stdout_artifact,
                                stderr_artifact,
                            ),
                            record=record,
                        )
                    )
                    observations.append(observation)
                    records.append(record)
                    all_artifacts.extend(stream_artifacts)
            finally:
                _unlock_source_snapshot(challenge_root)

        acceptance_evaluation = evaluate_rev_acceptance(
            spec=operator_spec,
            plan=plan,
            observations=observations,
            source_manifest_sha256=source_manifest_sha256,
            source_sha256=runtime_spec.source.sha256,
            source_size_bytes=runtime_spec.source.size_bytes,
            image_digest=image_digest,
        )
        private_evaluation = _runtime_evaluation(
            acceptance=acceptance_evaluation,
            runtime_spec=runtime_spec,
            runtime_spec_snapshot=spec_snapshot,
            accepted_input_snapshot=input_snapshot,
            expected_oracle=normalized_oracle,
            source_manifest_sha256=source_manifest_sha256,
            image_digest=image_digest,
            attestation=initial_attestation,
            scope_fingerprint=records[0]["scope_fingerprint"],
            records=records,
            additional_reason_codes=additional_reason_codes,
        )
        _validate_private_rev_runtime_proof_evaluation(private_evaluation)
        evaluation_payload = canonical_json_bytes(private_evaluation)
        evaluation_sha256 = sha256(evaluation_payload)
        evaluation_artifact_id = _new_id("A-rev-runtime-evaluation")
        evaluation_path = artifact_root / "evaluation.json"
        pending_artifacts.append(
            ArtifactReference(
                id=evaluation_artifact_id,
                path=evaluation_path.relative_to(paths.root).as_posix(),
                sha256="0" * 64,
                source_run_id=run_records[-1].run.id,
            )
        )
        atomic_write_bytes(
            evaluation_path,
            evaluation_payload,
            mode=0o400,
        )
        evaluation_artifact = ArtifactReference(
            id=evaluation_artifact_id,
            path=evaluation_path.relative_to(paths.root).as_posix(),
            sha256=evaluation_sha256,
            source_run_id=run_records[-1].run.id,
            size=len(evaluation_payload),
            media_type="application/json",
            extra=_artifact_extra(
                experiment_id=experiment_id,
                kind="rev_runtime_evaluation",
                evaluation_sha256=evaluation_sha256,
            ),
        )
        all_artifacts.append(evaluation_artifact)
        evaluation = _public_runtime_evaluation(
            private_evaluation,
            private_sha256=evaluation_sha256,
            private_size_bytes=len(evaluation_payload),
        )
        validate_rev_runtime_proof_evaluation(evaluation)
        evidence = {
            "base_revision": base_revision,
            "configuration_epoch": configuration_epoch,
            "evaluation": copy.deepcopy(evaluation),
            "experiment_id": experiment_id,
            "protocol": REV_RUNTIME_PROOF_PROTOCOL,
            "schema_version": REV_RUNTIME_PROOF_SCHEMA_VERSION,
        }
        experiment = Experiment(
            id=experiment_id,
            hypothesis_ids=[],
            command="ctfos engine rev-runtime-proof",
            expected_observation=(
                "three exact runtime acceptances and three fixed mutation "
                "rejections"
            ),
            keep_if="the hash-bound candidate-free 3+3 oracle passes",
            drop_if="any transport, source, runtime, or oracle binding differs",
            timeout_seconds=command_timeout,
            resource_class="standard",
            kind=ExperimentKind.PROBE,
            status=(
                ExperimentStatus.COMPLETED
                if evaluation["passed"]
                else ExperimentStatus.FAILED
            ),
            result={REV_RUNTIME_PROOF_RESULT_KEY: evidence},
            artifact_ids=[],
            evidence_run_ids=[],
            evidence_receipt_ids=[],
            evaluation_reason=(
                "rev_runtime_proof:passed"
                if evaluation["passed"]
                else (
                    "rev_runtime_proof:"
                    + ",".join(evaluation["reason_codes"])
                )[:512]
            ),
            evaluated_at=utc_now(),
            extra={
                "context_visibility": "commitment_only",
                "engine_executor": REV_RUNTIME_PROOF_EXECUTOR,
                "protocol": REV_RUNTIME_PROOF_PROTOCOL,
            },
        )

        _require_incoming_current(
            engine,
            state,
            runtime_spec,
            expected_manifest_sha256=source_manifest_sha256,
        )
        _require_workspace_current(source_client, spec_snapshot)
        final_attestation = _probe_runtime_capability(
            engine,
            image_digest,
        )
        if final_attestation != initial_attestation:
            raise RevRuntimeProofError(
                "runtime_capability_attestation_changed"
            )

        def commit(current: ChallengeState) -> None:
            if (
                current.revision != base_revision
                or current.configuration_epoch != configuration_epoch
                or current.status is not before_status
                or current.primary_target_id is not None
                or tuple(item.id for item in current.targets)
                != before_target_ids
                or tuple(item.id for item in current.candidates)
                != before_candidate_ids
                or tuple(item.id for item in current.submissions)
                != before_submission_ids
                or engine.config.runtime.image_digest != image_digest
            ):
                raise RevRuntimeProofError(
                    "runtime_state_changed_before_commit"
                )
            _require_incoming_current(
                engine,
                current,
                runtime_spec,
                expected_manifest_sha256=source_manifest_sha256,
            )
            _require_workspace_current(source_client, spec_snapshot)
            for snapshot, maximum in (
                (spec_snapshot, REV_RUNTIME_V1_MAX_DOCUMENT_BYTES),
                (input_snapshot, REV_ACCEPTANCE_MAX_INPUT_BYTES),
            ):
                read_bounded_regular(
                    paths.root,
                    snapshot.path,
                    maximum_bytes=maximum,
                    expected_sha256=snapshot.sha256,
                    expected_size=snapshot.size_bytes,
                )
            read_bounded_regular(
                paths.root,
                evaluation_artifact.path,
                maximum_bytes=REV_ACCEPTANCE_MAX_EVIDENCE_BYTES,
                expected_sha256=evaluation_artifact.sha256,
                expected_size=evaluation_artifact.size or 0,
            )
            current.artifacts.extend(all_artifacts)
            current.runs.extend(item.run for item in run_records)
            current.experiments.append(experiment)
            validate_rev_runtime_proof_state_graph(current)

        committed = engine.store.update(
            identity,
            commit,
            expected_revision=base_revision,
        )
        committed_state = True
        if (
            committed.status is not before_status
            or tuple(item.id for item in committed.candidates)
            != before_candidate_ids
            or tuple(item.id for item in committed.submissions)
            != before_submission_ids
            or committed.primary_target_id is not None
        ):
            raise RevRuntimeProofError(
                "runtime_authority_boundary_broken"
            )
        return committed, evaluation
    except BaseException as error:
        if not committed_state:
            try:
                engine._cleanup_uncommitted_artifacts(
                    identity,
                    pending_artifacts,
                    cause=error,
                )
            except BaseException as cleanup_error:
                error.add_note(
                    "Rev runtime artifact cleanup failed: "
                    f"{type(cleanup_error).__name__}"
                )
            try:
                engine._cleanup_uncommitted_pwn_crash_runs(
                    identity,
                    pending_run_ids,
                    cause=error,
                )
            except BaseException as cleanup_error:
                error.add_note(
                    "Rev runtime run cleanup failed: "
                    f"{type(cleanup_error).__name__}"
                )
        raise
    finally:
        if lock is not None:
            lock.release()


__all__ = [
    "REV_RUNTIME_EXEC_ARGV",
    "REV_RUNTIME_EXEC_ATTESTATION",
    "REV_RUNTIME_EXEC_CAPABILITY",
    "REV_RUNTIME_EXEC_SHA256",
    "REV_RUNTIME_PROOF_EXECUTOR",
    "REV_RUNTIME_PROOF_MAX_TIMEOUT_SECONDS",
    "REV_RUNTIME_PROOF_PROTOCOL",
    "REV_RUNTIME_PROOF_RESULT_KEY",
    "REV_RUNTIME_PROOF_SCHEMA_VERSION",
    "RevRuntimeProofError",
    "prove_rev_runtime_accepted_input",
    "rev_runtime_proof_state_errors",
    "validate_rev_runtime_proof_evaluation",
    "validate_rev_runtime_proof_state_graph",
]
