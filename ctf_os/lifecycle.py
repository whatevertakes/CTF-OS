"""Checkpoint, pause handoff, closure, and export helpers."""

from __future__ import annotations

import copy
import errno
import json
import os
import stat
import uuid
from pathlib import Path
from typing import Any

from ctf_os.engine.challenge import (
    ChallengeEngine,
    EngineError,
    SessionAlreadyRunning,
)
from ctf_os.engine.checkpoint_projection import (
    checkpoint_action_projection_metadata,
    checkpoint_action_references,
)
from ctf_os.models import (
    ACTIVE_HYPOTHESIS_STATUSES,
    ChallengeIdentity,
    Checkpoint,
    ClosureBundle,
    ClosureCompleteness,
    ExperimentStatus,
    FactKind,
    RunOrigin,
    utc_now,
)
from ctf_os.sandbox.files import copy_bounded_regular
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.store import (
    MAX_CANONICAL_STATE_BYTES,
    ChallengeLock,
    LockTimeout,
    sha256_file,
)
from ctf_os.store.atomic import (
    atomic_write_json,
    atomic_write_text,
    canonical_json_bytes,
    read_json,
)
from ctf_os.store.locks import FileLock
from ctf_os.store.views import render_current_markdown


MAX_PORTABLE_CLOSURE_BYTES = 64 * 1024 * 1024
_HANDOFF_TEMPORARY_TOKEN_HEX_CHARS = 32


def _nearest_existing_handoff_directory(path: Path) -> Path:
    candidate = path.parent
    while True:
        try:
            metadata = candidate.stat()
        except OSError as error:
            if error.errno not in {
                errno.ENOENT,
                errno.ENOTDIR,
                errno.ENAMETOOLONG,
            }:
                raise EngineError(
                    "handoff destination parent cannot be inspected"
                ) from error
        else:
            if not stat.S_ISDIR(metadata.st_mode):
                raise EngineError(
                    "handoff destination parent is not a directory"
                )
            return candidate
        parent = candidate.parent
        if parent == candidate:
            raise EngineError(
                "handoff destination has no usable parent directory"
            )
        candidate = parent


def _handoff_path_limit(directory: Path, name: str) -> int | None:
    try:
        value = os.pathconf(directory, name)
    except (OSError, ValueError) as error:
        raise EngineError(
            "handoff destination filesystem limits cannot be inspected"
        ) from error
    return value if value >= 0 else None


def _validate_handoff_path_limits(path: Path, directory: Path) -> None:
    name_max = _handoff_path_limit(directory, "PC_NAME_MAX")
    path_max = _handoff_path_limit(directory, "PC_PATH_MAX")
    components = path.parts[1:] if path.anchor else path.parts
    temporary_name = (
        f".{path.name}."
        f"{'0' * _HANDOFF_TEMPORARY_TOKEN_HEX_CHARS}.tmp"
    )
    if name_max is not None:
        for component in components:
            if len(os.fsencode(component)) > name_max:
                raise EngineError(
                    "handoff destination contains an overlong path component"
                )
        if len(os.fsencode(temporary_name)) > name_max:
            raise EngineError(
                "handoff destination filename is too long for atomic write"
            )
    if (
        path_max is not None
        and len(os.fsencode(os.fspath(path))) >= path_max
    ):
        raise EngineError("handoff destination path is too long")
    temporary_path = path.with_name(temporary_name)
    if (
        path_max is not None
        and len(os.fsencode(os.fspath(temporary_path))) >= path_max
    ):
        raise EngineError(
            "handoff destination leaves no room for an atomic temporary file"
        )


def _preflight_handoff_destination(destination: Path) -> Path:
    """Resolve predictable destination failures before canonical mutation."""

    try:
        expanded = Path(destination).expanduser()
        if "\x00" in os.fspath(expanded):
            raise EngineError("handoff destination contains a NUL byte")
        # Match ``Path.resolve(strict=False)`` lexical ``..`` handling before
        # inspecting ancestors; this keeps the established destination path
        # semantics while avoiding filesystem access to overlong components.
        absolute = Path(os.path.abspath(expanded))
        lexical_parent = _nearest_existing_handoff_directory(absolute)
        _validate_handoff_path_limits(absolute, lexical_parent)
        resolved = expanded.resolve()
        resolved_parent = _nearest_existing_handoff_directory(resolved)
        _validate_handoff_path_limits(resolved, resolved_parent)
        try:
            destination_metadata = resolved.stat()
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISDIR(destination_metadata.st_mode):
                raise EngineError(
                    "handoff destination must be a file, not a directory"
                )
        return resolved
    except EngineError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise EngineError("invalid handoff destination") from error


def _acquire_session_lock(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
) -> ChallengeLock:
    paths = engine.store.challenge_paths(identity)
    lock = ChallengeLock(paths.runtime / "session.lock", timeout=0)
    try:
        lock.acquire()
    except LockTimeout as error:
        raise SessionAlreadyRunning(
            f"another session already owns {identity.key}"
        ) from error
    return lock


def _closure_admission_reservation(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    portability: str,
) -> int:
    """Bound every accounted closure write before recovery or assembly.

    Two canonical-state-sized documents cover the simultaneously live
    assembling and ready intent generations.  A portable package additionally
    reserves the exact copied evidence bytes and one state-sized manifest.
    The hard state bound is deliberately conservative, but makes the
    reservation independent of JSON formatting and artifact-count growth.
    """

    current = engine.store.load(identity)
    replace_automatic = (
        current.closure is not None
        and current.closure.completeness
        is ClosureCompleteness.INCOMPLETE
        and current.closure.extra.get("automatic_incomplete") is True
    )
    if current.closure is not None and not replace_automatic:
        return 0
    requested = 2 * MAX_CANONICAL_STATE_BYTES
    if portability == "portable":
        portable_ready, artifact_bytes = _portable_artifacts(
            engine,
            identity,
        )
        if portable_ready:
            requested += artifact_bytes + MAX_CANONICAL_STATE_BYTES
    return requested


def _export_admission_reservation(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    include_closure: bool,
    redacted: bool,
) -> int:
    """Reserve exact planned payloads, or hard bounds during recovery."""

    state = engine.store.load(identity)
    intent_root = _closure_intent_root(engine, identity)
    if intent_root.is_dir() and any(intent_root.glob("CLOSE-*.json")):
        # Reconciliation can install a ready closure before projection.  Its
        # exact post-recovery state is deliberately not predicted by this
        # read-only preflight, so use the documented hard bounds only for this
        # exceptional recovery path.
        requested = 2 * MAX_CANONICAL_STATE_BYTES
        if include_closure:
            requested += 2 * MAX_CANONICAL_STATE_BYTES
        return requested
    projection = _export_projection(
        state,
        include_closure=include_closure,
        redacted=redacted,
    )
    payload, summary, closure_payload, closure_manifest = projection
    documents = [payload]
    if closure_payload is not None:
        documents.append(closure_payload)
    if closure_manifest is not None:
        documents.append(closure_manifest)
    # These are the complete atomic temporary generations that may coexist
    # with prior exports. Existing export bytes are already in the inventory.
    return len(summary.encode("utf-8")) + sum(
        len(canonical_json_bytes(document)) for document in documents
    )


def _export_projection(
    state: Any,
    *,
    include_closure: bool,
    redacted: bool,
) -> tuple[
    dict[str, Any],
    str,
    dict[str, Any] | None,
    dict[str, Any] | None,
]:
    """Build and hard-bound every accounted export document in memory."""

    payload = copy.deepcopy(state.to_dict())
    if redacted:
        for candidate in payload.get("candidates", []):
            candidate["value"] = "[REDACTED]"
        payload["submissions"] = [
            {
                **item,
                "response": (
                    "[REDACTED]"
                    if item.get("response") is not None
                    else None
                ),
            }
            for item in payload.get("submissions", [])
        ]
    summary = render_current_markdown(state)
    if redacted:
        for candidate in sorted(
            state.candidates,
            key=lambda item: len(item.value),
            reverse=True,
        ):
            summary = summary.replace(candidate.value, "[REDACTED]")
    closure_payload: dict[str, Any] | None = None
    closure_manifest: dict[str, Any] | None = None
    if include_closure:
        if state.closure is None:
            raise EngineError("closure has not been recorded")
        closure_payload = state.closure.to_dict()
        closure_manifest = {
            "schema_version": 1,
            "closure_id": state.closure.id,
            "portability": state.closure.portability,
            "state_revision": state.revision,
            "redacted": redacted,
            "portable_package_path": (
                state.closure.extra.get("package_path")
                if not redacted
                else None
            ),
            "portable_package_manifest_sha256": (
                state.closure.extra.get("package_manifest_sha256")
                if not redacted
                else None
            ),
            "artifact_paths": [
                item.path
                for item in state.artifacts
                if item.id
                in {
                    *state.closure.source_artifact_ids,
                    *state.closure.solver_artifact_ids,
                    *state.closure.report_artifact_ids,
                }
            ],
        }
    documents = [payload]
    if closure_payload is not None:
        documents.append(closure_payload)
    if closure_manifest is not None:
        documents.append(closure_manifest)
    if any(
        len(canonical_json_bytes(value)) > MAX_CANONICAL_STATE_BYTES
        for value in documents
    ) or len(summary.encode("utf-8")) > MAX_CANONICAL_STATE_BYTES:
        raise EngineError("export projection exceeds its reserved byte bound")
    return payload, summary, closure_payload, closure_manifest


def _closure_intent_root(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
) -> Path:
    return (
        engine.store.challenge_paths(identity).runtime
        / "closure-intents"
    )


def _quarantine_closure_bundle(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    closure_id: str,
    *,
    reason: str,
) -> None:
    paths = engine.store.challenge_paths(identity)
    source = paths.artifacts / "closures" / closure_id
    if not source.exists():
        return
    destination = (
        paths.runtime / "quarantine" / "closures" / closure_id
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise EngineError(
            f"closure quarantine destination already exists: {closure_id}"
        )
    if source.stat().st_dev != destination.parent.stat().st_dev:
        raise EngineError("closure quarantine must remain on one filesystem")
    os.replace(source, destination)
    atomic_write_json(
        destination / "quarantine.json",
        {
            "schema_version": 1,
            "closure_id": closure_id,
            "reason": reason[:1024],
            "automatic_restore": False,
            "quarantined_at": utc_now(),
        },
    )


def _reconcile_closure_intents_locked(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
) -> Any:
    state = engine.store.load(identity)
    root = _closure_intent_root(engine, identity)
    if not root.is_dir():
        return state
    for path in sorted(root.glob("CLOSE-*.json")):
        raw = read_json(path)
        if not isinstance(raw, dict):
            raise EngineError(f"invalid closure intent: {path}")
        closure_id = raw.get("closure_id")
        if (
            not isinstance(closure_id, str)
            or not closure_id.startswith("CLOSE-")
            or "/" in closure_id
            or "\\" in closure_id
        ):
            raise EngineError("closure intent has an invalid id")
        state = engine.store.load(identity)
        ready_upgrade = (
            raw.get("status") == "ready"
            and isinstance(raw.get("closure"), dict)
            and state.closure is not None
            and state.closure.id == closure_id
            and state.closure.extra.get("automatic_incomplete") is True
        )
        if (
            state.closure is not None
            and state.closure.id == closure_id
            and not ready_upgrade
        ):
            path.unlink(missing_ok=True)
            continue
        closure_raw = raw.get("closure")
        expected_revision = raw.get("expected_state_revision")
        if (
            raw.get("status") == "ready"
            and isinstance(closure_raw, dict)
            and isinstance(expected_revision, int)
            and not isinstance(expected_revision, bool)
            and state.revision == expected_revision
        ):
            closure = ClosureBundle.from_dict(closure_raw)

            def apply(current: Any) -> None:
                if current.closure is not None:
                    if (
                        current.closure.id == closure.id
                        and current.closure.extra.get(
                            "automatic_incomplete"
                        )
                        is True
                    ):
                        current.closure = closure
                        return
                    raise EngineError(
                        "challenge already has a closure"
                    )
                current.closure = closure

            state = engine.store.update(
                identity,
                apply,
                expected_revision=expected_revision,
            )
            path.unlink(missing_ok=True)
            continue
        _quarantine_closure_bundle(
            engine,
            identity,
            closure_id,
            reason="stale or incomplete closure intent",
        )
        path.unlink(missing_ok=True)
    return engine.store.load(identity)


def _reconcile_closure_intents(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
) -> Any:
    paths = engine.store.challenge_paths(identity)
    with FileLock(paths.runtime / "closure.lock") as closure_lock:
        closure_lock.acquire()
        return _reconcile_closure_intents_locked(engine, identity)


def create_checkpoint(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    note: str | None = None,
) -> tuple[Any, Checkpoint]:
    current = engine.store.load(identity)
    if current.schema_version < STATE_SCHEMA_VERSION:
        raise EngineError("checkpoints require state schema v2")
    checkpoint = Checkpoint(
        id=f"CP-operator-{uuid.uuid4().hex[:16]}",
        session_id=current.active_managed_session_id,
        cycle_id=None,
        active_goal_id=current.active_goal_id,
        open_hypothesis_ids=[
            item.id
            for item in current.hypotheses
            if item.status in ACTIVE_HYPOTHESIS_STATUSES
        ],
        observation_fact_ids=[
            item.id
            for item in current.facts
            if item.kind is FactKind.OBSERVATION
        ][-50:],
        next_actions=checkpoint_action_references(
            item
            for item in current.experiments
            if item.status is ExperimentStatus.REGISTERED
        )[:20],
        do_not_repeat=checkpoint_action_references(
            item
            for item in current.experiments
            if item.status
            in {
                ExperimentStatus.COMPLETED,
                ExperimentStatus.AWAITING_EVALUATION,
                ExperimentStatus.KEPT,
                ExperimentStatus.DROPPED,
                ExperimentStatus.FAILED,
            }
        )[-20:],
        artifact_ids=[item.id for item in current.artifacts[-50:]],
        receipt_ids=[item.id for item in current.receipts[-50:]],
        note=note,
        extra=checkpoint_action_projection_metadata(),
    )

    def apply(state: Any) -> None:
        state.checkpoints.append(checkpoint)

    return (
        engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        ),
        checkpoint,
    )


def pause_with_handoff(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    destination: Path,
    *,
    note: str | None = None,
) -> Any:
    destination = _preflight_handoff_destination(destination)
    state, checkpoint = create_checkpoint(engine, identity, note=note)
    state = engine.pause(identity)
    payload = {
        "schema_version": 1,
        "identity": identity.to_dict(),
        "state_revision": state.revision,
        "status": state.status.value,
        "checkpoint": checkpoint.to_dict(),
        "state_path": str(engine.store.challenge_paths(identity).state),
        "created_at": utc_now(),
    }
    atomic_write_json(destination, payload)
    return state


def _portable_artifacts(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
) -> tuple[bool, int]:
    state = engine.store.load(identity)
    paths = engine.store.challenge_paths(identity)
    total = sum(item.size for item in state.source_inventory)
    if total > MAX_PORTABLE_CLOSURE_BYTES:
        return False, total
    seen_paths: set[str] = set()
    for artifact in state.artifacts:
        if artifact.path in seen_paths:
            continue
        seen_paths.add(artifact.path)
        candidate = paths.root / artifact.path
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(paths.root.resolve(strict=True))
            metadata = resolved.stat(follow_symlinks=False)
        except (OSError, ValueError):
            return False, total
        if not resolved.is_file() or resolved.is_symlink():
            return False, total
        total += metadata.st_size
        if total > MAX_PORTABLE_CLOSURE_BYTES:
            return False, total
    return True, total


def _build_portable_bundle(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    closure_id: str,
    expected_state_revision: int,
    expected_copy_bytes: int,
) -> tuple[str, str]:
    """Copy all source and evidence bytes into one bounded immutable bundle."""

    state = engine.store.load(identity)
    if state.revision != expected_state_revision:
        raise EngineError("state changed before portable closure assembly")
    paths = engine.store.challenge_paths(identity)
    bundle = paths.artifacts / "closures" / closure_id
    bundle.mkdir(parents=True, exist_ok=False, mode=0o700)
    copied: list[dict[str, Any]] = []
    remaining = MAX_PORTABLE_CLOSURE_BYTES
    remaining_admission = expected_copy_bytes

    def source_admission(expected_size: int):
        def admit(actual_size: int) -> None:
            if actual_size != expected_size:
                raise EngineError(
                    "portable closure source size changed before copy"
                )
            engine._enforce_storage_admission(
                identity,
                requested_bytes=remaining_admission,
            )

        return admit

    for index, source in enumerate(state.source_inventory):
        if source.size > remaining:
            raise EngineError("portable closure exceeds byte limit")
        destination = bundle / "source" / f"{index:06d}.bin"
        snapshot = copy_bounded_regular(
            engine.challenge_input(identity),
            source.path,
            destination,
            maximum_bytes=max(1, remaining),
            expected_sha256=source.sha256,
            expected_size=source.size,
            source_size_admission=source_admission(source.size),
        )
        remaining -= snapshot.size_bytes
        remaining_admission -= snapshot.size_bytes
        copied.append(
            {
                "kind": "challenge_source",
                "source_path": source.path,
                "bundle_path": snapshot.path.relative_to(bundle).as_posix(),
                "sha256": snapshot.sha256,
                "bytes": snapshot.size_bytes,
            }
        )

    seen_paths: set[str] = set()
    for index, artifact in enumerate(state.artifacts):
        if artifact.path in seen_paths:
            continue
        seen_paths.add(artifact.path)
        if artifact.size is not None and artifact.size > remaining:
            raise EngineError("portable closure exceeds byte limit")
        expected_size = (
            artifact.size
            if artifact.size is not None
            else (paths.root / artifact.path).stat(follow_symlinks=False).st_size
        )
        destination = bundle / "evidence" / f"{index:06d}.bin"
        snapshot = copy_bounded_regular(
            paths.root,
            artifact.path,
            destination,
            maximum_bytes=max(1, remaining),
            expected_sha256=artifact.sha256,
            expected_size=artifact.size,
            source_size_admission=source_admission(expected_size),
        )
        remaining -= snapshot.size_bytes
        remaining_admission -= snapshot.size_bytes
        copied.append(
            {
                "kind": "artifact",
                "artifact_id": artifact.id,
                "source_path": artifact.path,
                "bundle_path": snapshot.path.relative_to(bundle).as_posix(),
                "sha256": snapshot.sha256,
                "bytes": snapshot.size_bytes,
            }
        )

    if remaining_admission != 0:
        raise EngineError("portable closure reservation did not match copied bytes")
    manifest_path = bundle / "manifest.json"
    atomic_write_json(
        manifest_path,
        {
            "schema_version": 1,
            "closure_id": closure_id,
            "identity": identity.to_dict(),
            "state_revision": state.revision,
            "source_manifest_sha256": state.metadata.get(
                "source_manifest_sha256"
            ),
            "image_reference": (
                engine.config.runtime.image_digest
                or engine.config.runtime.image
            ),
            "total_bytes": MAX_PORTABLE_CLOSURE_BYTES - remaining,
            "files": copied,
        },
    )
    return (
        bundle.relative_to(paths.root).as_posix(),
        sha256_file(manifest_path),
    )


def _close_challenge_locked(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    portability: str = "referential",
) -> Any:
    current = _reconcile_closure_intents_locked(engine, identity)
    if current.schema_version < STATE_SCHEMA_VERSION:
        raise EngineError("closure requires state schema v2")
    if portability not in {"portable", "referential"}:
        raise EngineError("closure portability must be portable or referential")
    replace_automatic = (
        current.closure is not None
        and current.closure.completeness
        is ClosureCompleteness.INCOMPLETE
        and current.closure.extra.get("automatic_incomplete") is True
    )
    if current.closure is not None and not replace_automatic:
        return current
    closure_id = (
        current.closure.id
        if replace_automatic and current.closure is not None
        else f"CLOSE-{uuid.uuid4().hex[:16]}"
    )
    intent = _closure_intent_root(
        engine,
        identity,
    ) / f"{closure_id}.json"
    portable_ready, artifact_bytes = _portable_artifacts(engine, identity)
    atomic_write_json(
        intent,
        {
            "schema_version": 1,
            "closure_id": closure_id,
            "identity": identity.to_dict(),
            "expected_state_revision": current.revision,
            "requested_portability": portability,
            "status": "assembling",
            "created_at": utc_now(),
        },
    )
    package_path: str | None = None
    package_manifest_sha256: str | None = None
    if portability == "portable" and portable_ready:
        try:
            package_path, package_manifest_sha256 = _build_portable_bundle(
                engine,
                identity,
                closure_id=closure_id,
                expected_state_revision=current.revision,
                expected_copy_bytes=artifact_bytes,
            )
        except (EngineError, OSError, ValueError) as error:
            portable_ready = False
            _quarantine_closure_bundle(
                engine,
                identity,
                closure_id,
                reason=(
                    "portable closure assembly failed: "
                    f"{type(error).__name__}"
                ),
            )
    effective_portability = (
        "portable"
        if (
            portability == "portable"
            and portable_ready
            and package_path is not None
            and package_manifest_sha256 is not None
        )
        else "referential"
    )
    proof_runs = [
        item.id for item in current.runs if item.origin is RunOrigin.PROOF
    ]
    complete = bool(
        current.source_inventory
        and engine.config.runtime.image_digest
        and current.checkpoints
        and (
            current.submissions
            or current.status.value not in {"SOLVED", "READY_TO_SUBMIT"}
        )
    )
    closure = ClosureBundle(
        id=closure_id,
        completeness=(
            ClosureCompleteness.COMPLETE
            if complete
            else ClosureCompleteness.INCOMPLETE
        ),
        portability=effective_portability,
        image_reference=(
            engine.config.runtime.image_digest
            or engine.config.runtime.image
        ),
        solver_artifact_ids=[
            item.id
            for item in current.artifacts
            if str(item.extra.get("purpose", "")).casefold()
            in {"solver", "exploit", "solution"}
        ],
        report_artifact_ids=[
            item.id
            for item in current.artifacts
            if str(item.extra.get("purpose", "")).casefold()
            in {"report", "writeup"}
        ],
        proof_run_ids=proof_runs,
        submission_ids=[item.id for item in current.submissions],
        target_ids=[item.id for item in current.targets],
        checkpoint_ids=[item.id for item in current.checkpoints],
        side_effect_receipt_ids=[item.id for item in current.receipts],
        extra={
            "source_manifest_sha256": current.metadata.get(
                "source_manifest_sha256"
            ),
            "artifact_bytes": artifact_bytes,
            "portable_requested": portability == "portable",
            "package_path": package_path,
            "package_manifest_sha256": package_manifest_sha256,
        },
    )

    def apply(state: Any) -> None:
        if state.closure is not None:
            if state.closure.id == closure.id:
                if (
                    state.closure.extra.get("automatic_incomplete")
                    is True
                ):
                    state.closure = closure
                return
            raise EngineError("challenge already has a closure")
        state.closure = closure

    atomic_write_json(
        intent,
        {
            "schema_version": 1,
            "closure_id": closure_id,
            "identity": identity.to_dict(),
            "expected_state_revision": current.revision,
            "requested_portability": portability,
            "status": "ready",
            "closure": closure.to_dict(),
            "created_at": utc_now(),
        },
    )
    try:
        committed = engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )
    except BaseException as error:
        try:
            recovered = engine.store.load(identity, recover=False)
            if (
                recovered.closure is not None
                and recovered.closure.id == closure_id
                and recovered.closure.to_dict()
                == closure.to_dict()
            ):
                intent.unlink(missing_ok=True)
                return recovered
        except BaseException as inspection_error:
            error.add_note(
                f"closure commit inspection failed: {inspection_error}"
            )
        # The ready intent and package remain durable for an exact retry.
        raise
    intent.unlink(missing_ok=True)
    return committed


def close_challenge(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    portability: str = "referential",
    _session_owned: bool = False,
) -> Any:
    if portability not in {"portable", "referential"}:
        raise EngineError("closure portability must be portable or referential")
    if not _session_owned:
        session_lock = _acquire_session_lock(engine, identity)
        try:
            requested = _closure_admission_reservation(
                engine,
                identity,
                portability=portability,
            )
            engine._enforce_storage_admission(
                identity,
                requested_bytes=requested,
            )
            return close_challenge(
                engine,
                identity,
                portability=portability,
                _session_owned=True,
            )
        finally:
            session_lock.release()
    paths = engine.store.challenge_paths(identity)
    with FileLock(paths.runtime / "closure.lock") as closure_lock:
        closure_lock.acquire()
        return _close_challenge_locked(
            engine,
            identity,
            portability=portability,
        )


def export_challenge(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    include_closure: bool = False,
    redacted: bool = False,
    _session_owned: bool = False,
) -> Path:
    if not _session_owned:
        session_lock = _acquire_session_lock(engine, identity)
        try:
            requested = _export_admission_reservation(
                engine,
                identity,
                include_closure=include_closure,
                redacted=redacted,
            )
            engine._enforce_storage_admission(
                identity,
                requested_bytes=requested,
            )
            return export_challenge(
                engine,
                identity,
                include_closure=include_closure,
                redacted=redacted,
                _session_owned=True,
            )
        finally:
            session_lock.release()
    state = _reconcile_closure_intents(engine, identity)
    paths = engine.store.challenge_paths(identity)
    payload, summary, closure_payload, closure_manifest = _export_projection(
        state,
        include_closure=include_closure,
        redacted=redacted,
    )
    engine.store.refresh_views(identity)
    atomic_write_json(paths.exports / "state.json", payload)
    atomic_write_text(paths.exports / "summary.md", summary)
    if closure_payload is not None and closure_manifest is not None:
        atomic_write_json(paths.exports / "closure.json", closure_payload)
        atomic_write_json(
            paths.exports / "closure-manifest.json",
            closure_manifest,
        )
    return paths.exports


__all__ = [
    "MAX_PORTABLE_CLOSURE_BYTES",
    "close_challenge",
    "create_checkpoint",
    "export_challenge",
    "pause_with_handoff",
]
