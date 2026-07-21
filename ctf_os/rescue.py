"""Exact-run, manually launched Claude rescue workspaces.

This module prepares data, sandboxes, and receipts.  It never launches or
supervises a model process and never promotes Claude output into Solve state.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager, nullcontext
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
from typing import Any, Iterator

from .contest import ChallengeSpec, ContestManifest
from .flags import matches_flag
from .preflight import prepared_tree_fingerprint
from .sandbox.network import parse_remotes, target_matches_observation
from .sandbox.preparation import (
    PreparedSandbox, prepare_sandbox_spec, validate_prepared_input,
)
from .sandbox.runtime import cleanup, create, probe_service_connectivity
from .service import ServiceActor, service_attachment
from .workspace import (
    CURRENT_FINGERPRINT_SCHEME, append_jsonl_fsync, atomic_json, atomic_text,
    challenge_workspace, read_jsonl_strict, safe_under, utc_now,
)


RESCUE_SCHEMA_VERSION = 1
RESCUE_LEDGER_SCHEMA_VERSION = 1
MAX_PACKET_BYTES = 128 * 1024
MAX_RETURN_BYTES = 128 * 1024
MAX_SELECTED_FILES = 200
MAX_SELECTED_BYTES = 256 * 1024 * 1024
MAX_SELECTED_TEXT_BYTES = 256 * 1024
MAX_AUTO_BINARY_BYTES = 16 * 1024 * 1024
MAX_CLAIMS = 100
MODES = frozenset({
    "BLOCKER_BREAK", "PRIMITIVE_TO_POC", "REMOTE_ENDGAME",
    "FRESH_REINTERPRETATION", "FLAG_VERIFICATION",
})
PROFILES = frozenset({"standard", "deep"})
VERDICTS = frozenset({
    "REMOTE_FLAG_OBTAINED", "REMOTE_READY_HANDOFF", "CONFIRMED_BREAKTHROUGH",
    "NO_NEW_PATH", "ERROR",
})
LEDGER_EVENTS = frozenset({
    "RESCUE_PREPARED", "RESCUE_SANDBOX_READY", "RESCUE_RETURN_VALIDATED",
    "RESCUE_HANDED_BACK", "RESCUE_CONFIRMED", "RESCUE_REFUTED",
    "RESCUE_CLOSED", "RESCUE_ERROR",
})
IMMUTABLE_STATUSES = frozenset({
    "ACCEPTED", "SEALED", "SEALED_CLEAN", "SOLVED", "SUBMISSION_RECOMMENDED",
    "FULLY_VERIFIED", "TERMINATION_PENDING", "TERMINATED",
})
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class RescueError(ValueError):
    pass


def canonical_json(value: object) -> bytes:
    """Deterministic UTF-8 JSON used for rescue identities and packet digests."""

    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def calculate_packet_digest(packet: Mapping[str, Any]) -> str:
    """Hash canonical JSON after removing only the top-level packet_digest."""

    material = dict(packet)
    material.pop("packet_digest", None)
    return hashlib.sha256(canonical_json(material)).hexdigest()


def rescue_attempt_id(run_id: str, operation_id: str) -> str:
    digest = hashlib.sha256(f"{run_id}\0{operation_id}".encode()).hexdigest()[:20]
    return f"rescue-{digest}"


def prepare_rescue(
    repo_root: Path,
    manifest: ContestManifest,
    challenge: ChallengeSpec,
    record: Mapping[str, object],
    run: Path,
    *,
    mode: str,
    profile: str,
    objective: str,
    current_blocker: str,
    operation_id: str,
    leading_exploit_path: str | None = None,
    paths_not_to_repeat: Sequence[str] = (),
    lead_model: str | None = None,
    sandbox_factory: Callable[..., dict[str, object]] = create,
    sandbox_cleanup: Callable[..., dict[str, object]] = cleanup,
    connectivity_probe: Callable[..., dict[str, object]] = probe_service_connectivity,
    sandbox_preparer: Callable[..., PreparedSandbox] = prepare_sandbox_spec,
    prepared_fingerprint_reader: Callable[[Path], str] = prepared_tree_fingerprint,
    service_inspector: Callable[..., dict[str, object]] | None = None,
    attachment_factory: Callable[..., Iterator[None]] = service_attachment,
) -> dict[str, Any]:
    """Create or idempotently resume one immutable manual rescue attempt."""

    normalized_mode = _enum(mode, MODES, "mode")
    normalized_profile = _enum(profile, PROFILES, "profile", preserve_case=True)
    normalized_operation = _text(operation_id, "operation_id", 256)
    normalized_objective = _text(objective, "objective", 2000)
    normalized_blocker = _text(current_blocker, "current_blocker", 2000)
    leading = _text(
        leading_exploit_path or normalized_objective,
        "leading_exploit_path", 2000,
    )
    requested_model = _text(
        lead_model or ("sonnet" if normalized_profile == "standard" else "claude-fable-5"),
        "lead_model", 160,
    )
    identity = validate_exact_live_mutable_run(run, challenge, record)
    _validate_rescue_base(run)
    validate_prepared_input(
        challenge_workspace(run), record,
        fingerprint_reader=prepared_fingerprint_reader,
    )
    rid = rescue_attempt_id(run.name, normalized_operation)
    rescue_root = run / "rescue" / rid
    if rescue_root.parent.parent != run:
        raise RescueError("rescue directory is not exact-run local")

    truth, experiments, state_summary, references = _truth_from_run(
        run, leading_exploit_path=leading,
    )
    selected = _selected_manifest(run, references, rescue_root=rescue_root)
    request = {
        "mode": normalized_mode,
        "profile": normalized_profile,
        "objective": normalized_objective,
        "current_blocker": normalized_blocker,
        "leading_exploit_path": leading,
        "paths_not_to_repeat": [
            _text(item, "paths_not_to_repeat", 1000)
            for item in list(paths_not_to_repeat)[:20]
        ],
        "requested_lead_model": requested_model,
    }
    packet = {
        "schema_version": RESCUE_SCHEMA_VERSION,
        "identity": {
            "rescue_attempt_id": rid,
            "rescue_operation_id": normalized_operation,
            "operation_id": normalized_operation,
            "contest": str(manifest.slug),
            **identity,
        },
        "request": request,
        "state": state_summary,
        "truth": truth,
        "decisive_experiments": experiments,
        "artifacts": [row for row in selected if row["kind"] == "artifact"],
        "evidence": [row for row in selected if row["kind"] == "evidence"],
        "authorized_targets": _bounded_targets(record.get("authorized_targets")),
        "model_policy": _model_policy(normalized_profile),
        "source_inventory": _source_inventory(run),
        "context_limits": {
            "packet_bytes": MAX_PACKET_BYTES,
            "selected_file_bytes": MAX_SELECTED_TEXT_BYTES,
            "selected_file_count": MAX_SELECTED_FILES,
            "selected_total_bytes": MAX_SELECTED_BYTES,
            "symlinks_allowed": False,
        },
        "packet_digest": "",
    }
    _bound_packet(packet)
    packet["packet_digest"] = calculate_packet_digest(packet)
    packet_bytes = _pretty_json_bytes(packet)
    if len(packet_bytes) > MAX_PACKET_BYTES:
        raise RescueError(
            f"bounded rescue packet exceeds {MAX_PACKET_BYTES} bytes: {len(packet_bytes)}"
        )

    with rescue_lock(run):
        rows = load_rescue_ledger(run)
        existing = next((
            row for row in rows
            if row.get("operation_id") == normalized_operation
            and row.get("event") == "RESCUE_PREPARED"
        ), None)
        if existing is not None:
            if (
                existing.get("rescue_attempt_id") != rid
                or existing.get("packet_digest") != packet["packet_digest"]
            ):
                raise RescueError(
                    "operation_id already exists with conflicting canonical rescue material; "
                    "use a new operation-id"
                )
            saved = _load_packet(rescue_root)
            if canonical_json(saved) != canonical_json(packet):
                raise RescueError(
                    "immutable rescue packet conflicts with current canonical material; "
                    "use a new operation-id"
                )
        else:
            if rescue_root.exists():
                raise RescueError("rescue directory exists without its authoritative prepare receipt")
            _create_workspace(
                repo_root, run, rescue_root, challenge, packet, selected,
            )
            _append_event_unlocked(
                run, packet, "RESCUE_PREPARED",
                details={
                    "mode": normalized_mode, "profile": normalized_profile,
                    "requested_lead_model": requested_model,
                    "path": str(rescue_root),
                },
            )
        metadata_path = rescue_root / "sandbox.json"
        if metadata_path.is_file() and not metadata_path.is_symlink():
            metadata = _load_json(metadata_path, "rescue sandbox metadata")
            _validate_rescue_metadata(metadata, packet, rescue_root)
            if any(
                row.get("event") == "RESCUE_SANDBOX_READY"
                and row.get("rescue_attempt_id") == rid
                for row in load_rescue_ledger(run)
            ):
                return _prepare_response(run, rescue_root, packet, metadata, idempotent=True)

    managed = isinstance(record.get("service_plan"), Mapping) and record.get("service_plan", {}).get("kind") in {"dockerfile", "compose"}  # type: ignore[union-attr]
    prepare_kwargs: dict[str, Any] = {
        "repo_root": repo_root,
        "manifest": manifest,
        "challenge": challenge,
        "record": record,
        "workspace": challenge_workspace(run),
        "solve_root": run,
        "branch": rid,
        "branch_root": rescue_root,
        "session_id": rid,
        "parent_session_id": "sol-main",
        "session_role": "external",
        "require_running_managed_service": managed,
        "workspace_mode": "bind",
        "run_id": run.name,
        "rescue_attempt_id": rid,
        "external_solver": True,
        "solver_family": "claude",
        "session_kind": "external-rescue",
        "requested_lead_model": requested_model,
        "prepared_fingerprint_reader": prepared_fingerprint_reader,
    }
    if service_inspector is not None:
        prepare_kwargs["service_inspector"] = service_inspector
    metadata: dict[str, object] | None = None
    try:
        prepared = sandbox_preparer(**prepare_kwargs)
        guard = (
            attachment_factory(
                prepared.attachment_service,
                actor=ServiceActor(
                    session_id="sol-main", role="sol", parent_session_id="sol-main",
                ),
            )
            if prepared.attachment_service is not None else nullcontext()
        )
        with guard:
            metadata = sandbox_factory(prepared.spec)
            _validate_rescue_metadata(metadata, packet, rescue_root)
            if prepared.spec.service_network:
                metadata["connectivity_probe"] = connectivity_probe(metadata)
                atomic_json(Path(str(metadata["metadata_path"])), metadata)
    except Exception as exc:
        cleanup_error = None
        if metadata is not None:
            try:
                sandbox_cleanup(
                    metadata, session_id=rid, session_role="external",
                )
            except Exception as cleanup_exc:
                cleanup_error = str(cleanup_exc)[:2000]
        with rescue_lock(run):
            _append_event_unlocked(
                run, packet, "RESCUE_ERROR",
                details={
                    "phase": "sandbox_prepare", "error": str(exc)[:2000],
                    "failed_sandbox_cleanup_error": cleanup_error,
                },
            )
        raise
    with rescue_lock(run):
        _append_event_unlocked(
            run, packet, "RESCUE_SANDBOX_READY",
            details={
                "sandbox_metadata": "sandbox.json",
                "container": metadata.get("name"),
                "workspace_mode": metadata.get("workspace_mode"),
                "managed_service_attached": bool(metadata.get("service_network")),
            },
        )
    return _prepare_response(run, rescue_root, packet, metadata, idempotent=False)


def validate_exact_live_mutable_run(
    run: Path,
    challenge: ChallengeSpec,
    record: Mapping[str, object],
) -> dict[str, Any]:
    """Pure exact-run identity/mutability gate used before any rescue mutation."""

    run = run.resolve(strict=False)
    if run.is_symlink() or not run.is_dir() or run.parent.name != "runs":
        raise RescueError(f"exact run {run.name!r} is missing or unsafe")
    if not (run / "STATE.json").is_file() or not (run / "RUN_MANIFEST.json").is_file():
        raise RescueError(f"run {run.name}: exact run state or manifest is missing")
    state = _load_json(run / "STATE.json", "run state")
    manifest = _load_json(run / "RUN_MANIFEST.json", "run manifest")
    run_id = _identifier(state.get("run_id"), "run_id")
    if run_id != run.name:
        raise RescueError(f"run {run.name}: STATE.json run identity mismatch")
    challenge_identity = manifest.get("challenge")
    manifest_identity = manifest.get("identity")
    repository = manifest.get("repository")
    if not all(isinstance(value, Mapping) for value in (
        challenge_identity, manifest_identity, repository,
    )):
        raise RescueError(f"run {run_id}: RUN_MANIFEST.json identity is malformed")
    expected = {
        "challenge_id": challenge.id,
        "input_fingerprint": record.get("source_fingerprint"),
    }
    for field, value in expected.items():
        if state.get(field) != value or challenge_identity.get(field) != value:
            reason = "stale input fingerprint" if field == "input_fingerprint" else "mismatched challenge identity"
            raise RescueError(f"run {run_id}: {reason}")
    if state.get("challenge_id") != challenge.id:
        raise RescueError(f"run {run_id}: mismatched challenge identity")
    revision = state.get("target_revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise RescueError(f"run {run_id}: target revision is malformed")
    if challenge_identity.get("target_revision") != revision:
        raise RescueError(f"run {run_id}: changed target revision")
    revisions = read_jsonl_strict(
        challenge_workspace(run) / "target-revisions.jsonl", "target revision ledger",
    )
    if revisions and revisions[-1].get("target_revision") != revision:
        raise RescueError(f"run {run_id}: changed target revision")
    if state.get("fingerprint_scheme") != CURRENT_FINGERPRINT_SCHEME:
        raise RescueError(f"run {run_id}: stale fingerprint scheme")
    attempt_id = state.get("attempt_id") or manifest.get("attempt_id")
    instance_id = state.get("challenge_instance_id") or manifest.get("challenge_instance_id")
    if (
        not isinstance(attempt_id, str) or not attempt_id
        or not isinstance(instance_id, str) or not instance_id
        or manifest_identity.get("attempt_id") != attempt_id
        or manifest_identity.get("challenge_instance_id") != instance_id
        or manifest_identity.get("run_id") != run_id
    ):
        raise RescueError(f"run {run_id}: attempt or challenge instance identity mismatch")
    arm = str(manifest.get("arm") or "")
    if (
        arm != "LIVE" or manifest.get("matched_block_id") is not None
        or str(manifest.get("stratum") or "") != "LIVE_CONTEST"
    ):
        raise RescueError(f"run {run_id}: Claude rescue is allowed only for LIVE competition runs")
    _ensure_mutable(run, state)
    state_snapshot = state.get("challenge_snapshot_digest")
    manifest_snapshot = manifest.get("challenge_snapshot_digest")
    if state_snapshot is not None and manifest_snapshot is not None and state_snapshot != manifest_snapshot:
        raise RescueError(f"run {run_id}: challenge snapshot identity mismatch")
    snapshot = state_snapshot or manifest_snapshot
    if not isinstance(snapshot, str) or not _SHA256.fullmatch(snapshot):
        raise RescueError(f"run {run_id}: challenge snapshot digest is missing or malformed")
    commit = repository.get("commit_sha")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RescueError(f"run {run_id}: repository commit SHA is missing or malformed")
    manifest_seed = manifest.get("transformation_seed")
    state_seed = state.get("transformation_seed", "NONE")
    if manifest_seed is not None and str(manifest_seed) != str(state_seed):
        raise RescueError(f"run {run_id}: transformation seed identity mismatch")
    manifest_mode = manifest.get("mode")
    state_mode = state.get("solve_mode")
    if manifest_mode is not None and state_mode is not None and str(manifest_mode) != str(state_mode):
        raise RescueError(f"run {run_id}: solve mode identity mismatch")
    return {
        "run_id": run_id,
        "attempt_id": attempt_id,
        "challenge_instance_id": instance_id,
        "challenge_id": challenge.id,
        "challenge_key": str(challenge.key),
        "category": str(challenge.category),
        "input_fingerprint": str(state["input_fingerprint"]),
        "fingerprint_scheme": str(state["fingerprint_scheme"]),
        "target_revision": revision,
        "challenge_snapshot_digest": snapshot,
        "transformation_seed": str(state_seed),
        "solve_mode": str(state_mode or manifest_mode or ""),
        "repository_commit": commit,
    }


def show_rescue(run: Path, rescue_id: str) -> dict[str, Any]:
    rescue_root = _rescue_root(run, rescue_id)
    packet = _load_packet(rescue_root)
    if calculate_packet_digest(packet) != packet.get("packet_digest"):
        raise RescueError("immutable rescue packet digest mismatch")
    state = project_rescue_state(run, rescue_id)
    metadata_path = rescue_root / "sandbox.json"
    metadata = (
        _load_json(metadata_path, "rescue sandbox metadata")
        if metadata_path.is_file() and not metadata_path.is_symlink() else None
    )
    if metadata is not None:
        _validate_rescue_metadata(metadata, packet, rescue_root)
    request = packet["request"]
    return {
        "rescue_attempt_id": rescue_id,
        "operation_id": packet["identity"]["operation_id"],
        "run_id": run.name,
        "attempt_id": packet["identity"]["attempt_id"],
        "challenge_instance_id": packet["identity"]["challenge_instance_id"],
        "mode": request["mode"], "profile": request["profile"],
        "status": state["status"],
        "requested_lead_model": request["requested_lead_model"],
        "observed_lead_model": state.get("observed_lead_model"),
        "runtime_observation_evidence": state.get("runtime_observation_evidence"),
        "fallback_observed": state.get("fallback_observed"),
        "packet_digest": packet["packet_digest"],
        "sandbox_state": state["sandbox_state"],
        "return_file_state": _return_file_state(rescue_root),
        "start_command": _start_command(rescue_root, str(request["requested_lead_model"])),
        "fallback_command": _fallback_command(rescue_root, str(request["profile"])),
        "resume_command": _resume_command(packet),
        "validation_state": state["validation_state"],
        "path": str(rescue_root),
        "process_state_inferred": False,
    }


def validate_rescue_return(
    run: Path,
    challenge: ChallengeSpec,
    rescue_id: str,
) -> dict[str, Any]:
    """Validate candidate insight and write only rescue-local handback files."""

    rescue_root = _rescue_root(run, rescue_id)
    packet = _load_packet(rescue_root)
    digest = calculate_packet_digest(packet)
    if packet.get("packet_digest") != digest:
        raise RescueError("rescue return packet digest mismatch: immutable packet changed")
    _validate_packet_against_current_run(run, packet, challenge)
    result = _load_json(
        rescue_root / "CLAUDE_RETURN.json", "CLAUDE_RETURN.json",
        maximum=MAX_RETURN_BYTES,
    )
    _validate_return_shape(result)
    identity = packet["identity"]
    for field in (
        "rescue_attempt_id", "run_id", "challenge_instance_id",
        "input_fingerprint", "target_revision",
    ):
        if result.get(field) != identity.get(field):
            raise RescueError(f"Claude return wrong {field} identity")
    if result.get("packet_digest") != digest:
        raise RescueError("rescue return packet digest mismatch")
    if result.get("requested_lead_model") != packet["request"]["requested_lead_model"]:
        raise RescueError("Claude return requested model does not match the packet")
    _validate_model_observation(rescue_root, result)

    artifact_rows = _validate_return_artifacts(rescue_root, result.get("artifacts"))
    _validate_return_evidence(rescue_root, result)
    verdict = str(result["verdict"])
    validation: dict[str, Any] = {
        "verdict": verdict, "artifact_count": len(artifact_rows),
        "candidate_insight_only": True, "automatic_promotion": False,
    }
    if verdict == "REMOTE_FLAG_OBTAINED":
        validation["remote_flag"] = _validate_remote_flag_claim(
            rescue_root, packet, challenge, result, artifact_rows,
        )
    elif verdict == "REMOTE_READY_HANDOFF":
        validation["remote_ready"] = _validate_remote_ready(
            packet, result, artifact_rows,
        )
    elif verdict == "CONFIRMED_BREAKTHROUGH":
        experiments = result.get("decisive_experiments")
        if not isinstance(experiments, list) or not experiments:
            raise RescueError("CONFIRMED_BREAKTHROUGH requires a decisive experiment")
        if not any(_experiment_has_evidence(rescue_root, row) for row in experiments):
            raise RescueError("CONFIRMED_BREAKTHROUGH requires existing decisive evidence")

    return_digest = hashlib.sha256(canonical_json(result)).hexdigest()
    resume = _render_resume(run, rescue_root, packet, result, validation)
    idempotent = False
    with rescue_lock(run):
        existing = next((
            row for row in load_rescue_ledger(run)
            if row.get("rescue_attempt_id") == rescue_id
            and row.get("event") == "RESCUE_RETURN_VALIDATED"
        ), None)
        if existing is not None:
            existing_details = existing.get("details")
            if (
                not isinstance(existing_details, Mapping)
                or existing_details.get("return_digest") != return_digest
            ):
                raise RescueError(
                    "validated Claude return changed; preserve the prior result and create a new rescue attempt"
                )
            idempotent = True
        atomic_text(rescue_root / "CODEX-RESUME.md", resume)
        if existing is None:
            _append_event_unlocked(
                run, packet, "RESCUE_RETURN_VALIDATED",
                details={
                    **validation,
                    "return_digest": return_digest,
                    "observed_lead_model": result.get("observed_lead_model"),
                    "runtime_observation_evidence": result.get("runtime_observation_evidence"),
                    "fallback_observed": result.get("fallback_observed"),
                },
            )
            _append_event_unlocked(
                run, packet, "RESCUE_HANDED_BACK",
                details={
                    "resume_path": "CODEX-RESUME.md", "verdict": verdict,
                    "return_digest": return_digest,
                },
            )
    return {
        "run_id": run.name, "rescue_attempt_id": rescue_id,
        "packet_digest": digest, "verdict": verdict,
        "return_digest": return_digest, "idempotent": idempotent,
        "validation": validation,
        "codex_resume_path": str(rescue_root / "CODEX-RESUME.md"),
        "state_or_candidates_modified": False,
        "milestone_or_flag_receipt_created": False,
        "automatic_submission_attempted": False,
    }


def close_rescue(
    run: Path,
    rescue_id: str,
    *,
    reason: str,
    sandbox_cleanup: Callable[..., dict[str, object]] = cleanup,
) -> dict[str, Any]:
    normalized = _enum(
        reason, frozenset({"integrated", "refuted", "no-new-path", "manual"}),
        "reason", preserve_case=True,
    )
    rescue_root = _rescue_root(run, rescue_id)
    packet = _load_packet(rescue_root)
    state = project_rescue_state(run, rescue_id)
    if state.get("status") == "CLOSED":
        return {
            "run_id": run.name, "rescue_attempt_id": rescue_id,
            "closed": True, "reason": state.get("close_reason"), "idempotent": True,
            "workspace_preserved": True,
        }
    metadata = _load_json(rescue_root / "sandbox.json", "rescue sandbox metadata")
    _validate_rescue_metadata(metadata, packet, rescue_root)
    cleanup_receipt = sandbox_cleanup(
        metadata, session_id=rescue_id, session_role="external",
    )
    with rescue_lock(run):
        if normalized == "integrated":
            _append_event_unlocked(
                run, packet, "RESCUE_CONFIRMED",
                details={"reason": normalized},
            )
        elif normalized in {"refuted", "no-new-path"}:
            _append_event_unlocked(
                run, packet, "RESCUE_REFUTED",
                details={"reason": normalized},
            )
        _append_event_unlocked(
            run, packet, "RESCUE_CLOSED",
            details={"reason": normalized, "cleanup_receipt": cleanup_receipt},
        )
    return {
        "run_id": run.name, "rescue_attempt_id": rescue_id,
        "closed": True, "reason": normalized,
        "cleanup_receipt": cleanup_receipt, "idempotent": False,
        "workspace_preserved": True,
    }


def load_rescue_ledger(run: Path) -> list[dict[str, Any]]:
    _validate_rescue_base(run)
    rows = read_jsonl_strict(
        run / "rescue" / "RESCUE_LEDGER.jsonl", "rescue ledger",
    )
    for row in rows:
        if (
            row.get("schema_version") != RESCUE_LEDGER_SCHEMA_VERSION
            or row.get("event") not in LEDGER_EVENTS
            or not isinstance(row.get("details"), dict)
        ):
            raise RescueError("rescue ledger contains an unsupported or malformed row")
    return rows


def project_rescue_state(run: Path, rescue_id: str) -> dict[str, Any]:
    rescue_root = _rescue_root(run, rescue_id, require_packet=False)
    rows = [
        row for row in load_rescue_ledger(run)
        if row.get("rescue_attempt_id") == rescue_id
    ]
    if not rows:
        raise RescueError(f"rescue attempt does not exist in run {run.name}: {rescue_id}")
    status = "PREPARED"
    sandbox_state = "NOT_READY"
    validation_state = "NOT_VALIDATED"
    observed_model = None
    runtime_evidence = None
    fallback_observed = None
    close_reason = None
    for row in rows:
        event = row["event"]
        details = row["details"]
        if event == "RESCUE_SANDBOX_READY":
            status, sandbox_state = "READY", "READY"
        elif event == "RESCUE_RETURN_VALIDATED":
            status, validation_state = "RETURN_VALIDATED", "VALIDATED"
            observed_model = details.get("observed_lead_model")
            runtime_evidence = details.get("runtime_observation_evidence")
            fallback_observed = details.get("fallback_observed")
        elif event == "RESCUE_HANDED_BACK":
            status = "HANDED_BACK"
        elif event == "RESCUE_CONFIRMED":
            status = "CONFIRMED"
        elif event == "RESCUE_REFUTED":
            status = "REFUTED"
        elif event == "RESCUE_CLOSED":
            status, sandbox_state = "CLOSED", "CLOSED"
            close_reason = details.get("reason")
        elif event == "RESCUE_ERROR" and status not in {"CLOSED", "CONFIRMED", "REFUTED"}:
            status = "ERROR"
    packet = _load_packet(rescue_root) if (rescue_root / "RESCUE_PACKET.json").is_file() else None
    state = {
        "schema_version": RESCUE_SCHEMA_VERSION,
        "rescue_attempt_id": rescue_id, "run_id": run.name,
        "status": status, "sandbox_state": sandbox_state,
        "validation_state": validation_state,
        "return_file_state": _return_file_state(rescue_root),
        "observed_lead_model": observed_model,
        "runtime_observation_evidence": runtime_evidence,
        "fallback_observed": fallback_observed,
        "close_reason": close_reason,
        "last_event_id": rows[-1].get("event_id"),
        "last_event": rows[-1].get("event"),
        "event_count": len(rows),
        "packet_digest": packet.get("packet_digest") if packet else None,
        "updated_at": rows[-1].get("created_at"),
    }
    atomic_json(rescue_root / "RESCUE_STATE.json", state)
    return state


@contextmanager
def rescue_lock(run: Path) -> Iterator[None]:
    path = run / ".RESCUE.lock"
    if path.is_symlink():
        raise RescueError("run-local rescue lock must not be a symlink")
    descriptor = os.open(
        path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    with os.fdopen(descriptor, "a+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _validate_rescue_base(run: Path) -> Path:
    base = run / "rescue"
    if base.is_symlink() or (base.exists() and not base.is_dir()):
        raise RescueError(f"run {run.name}: rescue ledger directory is unsafe")
    return base


def _append_event_unlocked(
    run: Path,
    packet: Mapping[str, Any],
    event: str,
    *,
    details: Mapping[str, Any],
) -> dict[str, Any]:
    if event not in LEDGER_EVENTS:
        raise RescueError(f"unsupported rescue ledger event: {event}")
    identity = packet["identity"]
    material = {
        "schema_version": RESCUE_LEDGER_SCHEMA_VERSION,
        "rescue_attempt_id": identity["rescue_attempt_id"],
        "operation_id": identity["operation_id"],
        "run_id": identity["run_id"],
        "challenge_instance_id": identity["challenge_instance_id"],
        "input_fingerprint": identity["input_fingerprint"],
        "target_revision": identity["target_revision"],
        "packet_digest": packet["packet_digest"],
        "event": event,
        "details": dict(details),
    }
    event_id = hashlib.sha256(canonical_json(material)).hexdigest()[:24]
    rows = load_rescue_ledger(run)
    existing = next((row for row in rows if row.get("event_id") == event_id), None)
    if existing is not None:
        return existing
    same_event = next((
        row for row in rows
        if row.get("rescue_attempt_id") == identity["rescue_attempt_id"]
        and row.get("event") == event
    ), None)
    if same_event is not None and event not in {"RESCUE_ERROR"}:
        raise RescueError(f"rescue event {event} already exists with conflicting details")
    row = {**material, "event_id": event_id, "created_at": utc_now()}
    append_jsonl_fsync(
        run / "rescue" / "RESCUE_LEDGER.jsonl", row, label="rescue ledger",
    )
    project_rescue_state(run, str(identity["rescue_attempt_id"]))
    return row


def _ensure_mutable(run: Path, state: Mapping[str, Any]) -> None:
    run_id = run.name
    status = str(state.get("status") or "").upper()
    competition = str(state.get("competition_state") or "").upper()
    solve_status = str(state.get("solve_status") or "").upper()
    if state.get("sealed"):
        raise RescueError(f"run {run_id}: sealed run cannot prepare Claude rescue")
    if status in IMMUTABLE_STATUSES or competition in IMMUTABLE_STATUSES:
        raise RescueError(f"run {run_id}: immutable {status or competition} run cannot prepare Claude rescue")
    if solve_status == "SOLVED":
        raise RescueError(f"run {run_id}: SOLVED run cannot prepare Claude rescue")
    if state.get("remote_flag_receipt") or state.get("submission_recommended"):
        raise RescueError(f"run {run_id}: verified remote flag or submission recommendation is immutable")
    receipts = run / "flag-receipts"
    if receipts.is_symlink():
        raise RescueError(f"run {run_id}: flag receipt directory is unsafe")
    if receipts.is_dir():
        for path in receipts.glob("remote-*.json"):
            if path.is_symlink() or not path.is_file():
                raise RescueError(f"run {run_id}: remote flag receipt is unsafe")
            row = _load_json(path, "remote flag receipt")
            if row.get("schema_version") == 2 and row.get("network_observed") is True:
                raise RescueError(f"run {run_id}: verified remote flag receipt already exists")
        for path in receipts.glob("submission-*.json"):
            row = _load_json(path, "submission receipt")
            if str(row.get("result") or "").upper() == "ACCEPTED":
                raise RescueError(f"run {run_id}: ACCEPTED run cannot prepare Claude rescue")
    terminal = run / "terminal-components.jsonl"
    for row in read_jsonl_strict(terminal, "terminal component receipt ledger"):
        if row.get("component") == "terminal" and row.get("status") == "CONVERGENCE_COMPLETE":
            raise RescueError(f"run {run_id}: terminal convergence is complete")


def _truth_from_run(
    run: Path,
    *,
    leading_exploit_path: str,
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]], dict[str, Any], list[tuple[str, str]]]:
    truth: dict[str, list[dict[str, Any]]] = {
        "confirmed": [], "candidates": [], "refuted": [], "untested": [],
    }
    references: list[tuple[str, str]] = []
    experiments: list[dict[str, Any]] = []
    rows = read_jsonl_strict(
        run / "milestone-receipts.jsonl", "milestone receipt ledger",
    )
    working_poc = False
    remote_attempted = False
    for row in rows:
        event = str(row.get("event_type") or "").upper()
        evidence = _relative_strings(row.get("evidence"), "milestone evidence")
        artifacts = _relative_strings(row.get("artifacts"), "milestone artifacts")
        references.extend((value, "evidence") for value in evidence)
        references.extend((value, "artifact") for value in artifacts)
        claim = {
            "source": "milestone-receipts.jsonl",
            "receipt_id": row.get("receipt_id"),
            "session_id": row.get("session_id"),
            "type": event,
            "summary": _bounded(str(row.get("summary") or ""), 2000),
            "evidence": evidence[:20], "artifacts": artifacts[:20],
            "command_digest": row.get("command_digest"),
            "output_digest": row.get("output_digest"),
            "output_excerpt": _bounded(str(row.get("output_excerpt") or ""), 4000),
        }
        linked = bool(
            evidence or artifacts or row.get("command_digest")
            or row.get("output_excerpt")
        )
        if event == "PRIMITIVE_CONFIRMED" and linked:
            claim["truth_level"] = "CONFIRMED"
            truth["confirmed"].append(claim)
        elif event == "WORKING_POC" and (artifacts or row.get("command_digest")):
            claim["truth_level"] = "CONFIRMED"
            truth["confirmed"].append(claim)
            working_poc = True
        elif event in {"PRIMITIVE_CANDIDATE", "FLAG_CANDIDATE"} or (
            event == "PRIMITIVE_CONFIRMED" and not linked
        ):
            claim["truth_level"] = "CANDIDATE"
            truth["candidates"].append(claim)
        elif event == "PRIMITIVE_REFUTED":
            claim["truth_level"] = "REFUTED"
            truth["refuted"].append(claim)
        elif event == "DECISIVE_EXPERIMENT":
            detail = row.get("details") if isinstance(row.get("details"), Mapping) else {}
            decision = str(detail.get("decision") or "").upper()
            experiment = {
                "receipt_id": row.get("receipt_id"),
                "summary": claim["summary"],
                "decision": decision or None,
                "command_argv": row.get("command_argv") if isinstance(row.get("command_argv"), list) else [],
                "output_digest": row.get("output_digest"),
                "output_excerpt": claim["output_excerpt"],
                "evidence": evidence[:20], "artifacts": artifacts[:20],
            }
            experiments.append(experiment)
            if decision in {"KILL", "REFUTED"}:
                claim["truth_level"] = "REFUTED"
                truth["refuted"].append(claim)
        elif event == "REMOTE_ATTEMPT":
            remote_attempted = True

    candidates_path = run / "candidates.json"
    flag_candidate = None
    if candidates_path.exists():
        payload = _load_json(candidates_path, "candidate store")
        candidates = payload.get("candidates")
        if not isinstance(candidates, list) or any(not isinstance(row, Mapping) for row in candidates):
            raise RescueError("candidate store is malformed")
        for row in candidates[:MAX_CLAIMS]:
            candidate = _bounded(str(row.get("candidate") or ""), 4096)
            if not candidate:
                continue
            status = str(row.get("status") or "").upper()
            claim = {
                "source": "candidates.json", "candidate_id": row.get("candidate_id"),
                "candidate": candidate, "status": status,
                "truth_level": "REFUTED" if status == "REFUTED" else "CANDIDATE",
            }
            truth["refuted" if status == "REFUTED" else "candidates"].append(claim)
            if status != "REFUTED":
                flag_candidate = candidate
    truth["untested"].append({
        "truth_level": "UNTESTED", "source": "operator_request",
        "summary": _bounded(leading_exploit_path, 2000),
        "reopen_condition": None,
    })
    state = _load_json(run / "STATE.json", "run state")
    return (
        {key: value[:MAX_CLAIMS] for key, value in truth.items()},
        experiments[:50],
        {
            "solve_status": state.get("status"),
            "working_poc": working_poc,
            "remote_ready": bool(working_poc and state.get("remote_flag_receipt") is None),
            "remote_attempted": remote_attempted,
            "flag_candidate": flag_candidate,
        },
        references,
    )


def _selected_manifest(
    run: Path,
    references: Sequence[tuple[str, str]],
    *,
    rescue_root: Path,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    included_files = 0
    included_bytes = 0
    for reference, kind in references:
        if reference in seen:
            continue
        seen.add(reference)
        path = _safe_path(run, reference, "referenced run evidence")
        if not path.exists():
            rows.append({
                "kind": kind, "relative_source_path": reference,
                "included": False, "reason_not_included": "referenced path is missing",
            })
            continue
        if path.is_symlink() or not path.is_file():
            raise RescueError(f"referenced {kind} is a symlink or special file: {reference}")
        size = path.stat().st_size
        digest = _sha256(path)
        text_file = _is_text_file(path)
        include = True
        reason = None
        if included_files >= MAX_SELECTED_FILES:
            include, reason = False, "automatic selected-file count limit reached"
        elif included_bytes + size > MAX_SELECTED_BYTES:
            include, reason = False, "automatic selected-byte limit reached"
        elif text_file and size > MAX_SELECTED_TEXT_BYTES:
            include, reason = False, "selected text exceeds per-file limit"
        elif not text_file and size > MAX_AUTO_BINARY_BYTES:
            include, reason = False, "binary artifact requires explicit bounded import"
        destination = f"context/selected/{reference}" if include else None
        row = {
            "kind": kind, "relative_source_path": reference,
            "size": size, "sha256": digest,
            "producer_session": _producer_session(reference),
            "included": include, "selected_path": destination,
            "reason_not_included": reason,
            "operator_include_command": (
                None if include else " ".join((
                    "install", "-D", "-m", "0400", "--",
                    shlex.quote(str(path)),
                    shlex.quote(str(rescue_root / "work" / "operator-included" / reference)),
                ))
            ),
        }
        rows.append(row)
        if include:
            included_files += 1
            included_bytes += size
    return rows


def _create_workspace(
    repo_root: Path,
    run: Path,
    rescue_root: Path,
    challenge: ChallengeSpec,
    packet: Mapping[str, Any],
    selected: Sequence[Mapping[str, Any]],
) -> None:
    if rescue_root.is_symlink():
        raise RescueError("rescue workspace must not be a symlink")
    for name in (
        "work", "evidence", "artifacts", "logs", "context", ".claude",
        ".claude/agents", "context/selected",
    ):
        path = rescue_root / name
        if path.is_symlink():
            raise RescueError(f"rescue workspace path must not be a symlink: {path}")
        path.mkdir(parents=True, exist_ok=True)
    for row in selected:
        if not row.get("included"):
            continue
        source = _safe_path(run, str(row["relative_source_path"]), "selected source")
        destination = _safe_path(
            rescue_root, str(row["selected_path"]), "selected destination",
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        _copy_file(source, destination)
        destination.chmod(0o444)
    atomic_json(rescue_root / "RESCUE_PACKET.json", packet)
    (rescue_root / "RESCUE_PACKET.json").chmod(0o444)
    context_payloads = {
        "run-summary.json": {
            "schema_version": 1,
            "identity": packet["identity"], "state": packet["state"],
            "authorized_targets": packet["authorized_targets"],
            "source_inventory": packet["source_inventory"],
        },
        "confirmed.json": packet["truth"]["confirmed"],
        "candidates.json": packet["truth"]["candidates"],
        "refuted.json": packet["truth"]["refuted"],
        "untested.json": packet["truth"]["untested"],
        "decisive-experiments.json": packet["decisive_experiments"],
        "artifact-manifest.json": {
            "artifacts": packet["artifacts"], "evidence": packet["evidence"],
        },
    }
    for name, payload in context_payloads.items():
        path = rescue_root / "context" / name
        atomic_json(path, payload)
        path.chmod(0o444)
    resources = Path(__file__).resolve().parent / "resources" / "claude-rescue"
    mode_file = resources / "modes" / str(packet["request"]["mode"]).lower().replace("_", "-")
    mode_text = _read_resource(mode_file.with_suffix(".md"))
    category = str(challenge.category).casefold()
    playbook_path = resources / "playbooks" / f"{category}.md"
    if not playbook_path.is_file():
        playbook_path = resources / "playbooks" / "misc.md"
    base = _read_resource(resources / "CLAUDE.base.md")
    identity_note = (
        f"\n## Exact assignment\n\n- Run: `{run.name}`\n"
        f"- Rescue: `{packet['identity']['rescue_attempt_id']}`\n"
        f"- Packet digest: `{packet['packet_digest']}`\n"
        f"- Mode/profile: `{packet['request']['mode']}` / `{packet['request']['profile']}`\n"
    )
    atomic_text(
        rescue_root / "CLAUDE.md",
        base + identity_note + "\n" + mode_text + "\n" + _read_resource(playbook_path),
    )
    atomic_text(rescue_root / "REQUEST.md", _render_request(packet))
    atomic_text(rescue_root / "MODEL_POLICY.md", _render_model_policy(packet))
    atomic_text(rescue_root / "START.md", _render_start(rescue_root, packet))
    shutil.copyfile(resources / "RETURN.schema.json", rescue_root / "RETURN.schema.json")
    (rescue_root / "RETURN.schema.json").chmod(0o444)
    atomic_json(rescue_root / "CLAUDE_RETURN.json", {})
    atomic_text(
        rescue_root / "CODEX-RESUME.md",
        "# Codex resume\n\nPending `rescue-return-validate`. Claude output is not confirmed Solve truth.\n",
    )
    atomic_json(rescue_root / ".claude" / "settings.json", _claude_settings())
    for name, content in _agent_files().items():
        atomic_text(rescue_root / ".claude" / "agents" / name, content)
    wrapper = _ctf_tool_wrapper(repo_root, rescue_root, packet)
    atomic_text(rescue_root / "ctf-tool", wrapper)
    (rescue_root / "ctf-tool").chmod(0o755)


def _render_request(packet: Mapping[str, Any]) -> str:
    request = packet["request"]
    truth = packet["truth"]
    lines = [
        "# Rescue request", "",
        f"- Mode: `{request['mode']}`", f"- Profile: `{request['profile']}`",
        f"- Exact objective: {request['objective']}",
        f"- Current blocker: {request['current_blocker']}",
        f"- Leading exploit path: {request['leading_exploit_path']}",
        "- Expected success: a verified remote flag or executable remote-ready handoff",
        "- Maximum initial hypotheses: 2",
        "- Maximum initial decisive experiments: 3",
        "- Expected final verdict: REMOTE_FLAG_OBTAINED, REMOTE_READY_HANDOFF, "
        "CONFIRMED_BREAKTHROUGH, NO_NEW_PATH, or ERROR", "",
        "## Paths not to repeat", "",
    ]
    paths = request.get("paths_not_to_repeat") or []
    lines.extend(f"- {item}" for item in paths) if paths else lines.append("- None recorded")
    for heading, key in (
        ("Confirmed facts", "confirmed"), ("Candidate claims", "candidates"),
        ("Refuted hypotheses", "refuted"), ("Untested paths", "untested"),
    ):
        lines.extend(["", f"## {heading}", ""])
        claims = truth[key]
        lines.extend(
            f"- [{row.get('truth_level')}] {row.get('summary') or row.get('candidate') or row.get('type')}"
            for row in claims
        ) if claims else lines.append("- None")
    lines.extend(["", "## Selected artifact/evidence references", ""])
    selected = [*packet["artifacts"], *packet["evidence"]]
    lines.extend(
        f"- `{row.get('relative_source_path')}` — sha256 `{row.get('sha256')}` — "
        + (f"selected as `{row.get('selected_path')}`" if row.get("included") else str(row.get("reason_not_included")))
        for row in selected
    ) if selected else lines.append("- None")
    return "\n".join(lines) + "\n"


def _render_model_policy(packet: Mapping[str, Any]) -> str:
    policy = packet["model_policy"]
    lines = [
        "# Model policy", "",
        f"- Profile: `{packet['request']['profile']}`",
        f"- Requested lead model: `{packet['request']['requested_lead_model']}`",
        f"- Lead role: {policy['lead_role']}",
        "- Available profile subagents: " + ", ".join(policy["subagents"]),
        "- Requested model is intent only; do not copy it into observed model fields.",
        "- Record observed model only with a real CLI evidence file.",
        "- Do not treat Claude Code `--fallback-model` as evidence of Fable cyber routing.",
        f"- Maximum active hypotheses: {policy['maximum_active_hypotheses']}",
        f"- Maximum initial decisive experiments: {policy['maximum_initial_decisive_experiments']}",
        f"- Maximum initial subagent invocations: {policy['maximum_initial_subagent_invocations']}",
        f"- Maximum concurrent Haiku subagents: {policy['maximum_concurrent_haiku']}",
        f"- Maximum Sonnet implementation subagents: {policy['maximum_sonnet_implementation']}",
        "- Main Claude integrates subagent results; subagent nesting is not assumed.",
    ]
    return "\n".join(lines) + "\n"


def _render_start(rescue_root: Path, packet: Mapping[str, Any]) -> str:
    start = _start_command(rescue_root, str(packet["request"]["requested_lead_model"]))
    lines = [
        "# Manual start", "",
        "CTF-OS did not start Claude. Pause or exit Codex, open a new terminal, and run:",
        "", "```bash", start, "```", "",
    ]
    if packet["request"]["profile"] == "deep":
        lines.extend([
            "", "If the Fable session explicitly refuses or cannot continue the authorized CTF task, "
            "exit it and start a new manually approved session with:", "", "```bash",
            f"cd {shlex.quote(str(rescue_root))}\nclaude --model opus", "```",
            "", "This is a manual alternative, not an automatic fallback or evidence of observed routing.",
        ])
    return "\n".join(lines) + "\n"


def _claude_settings() -> dict[str, Any]:
    return {
        "permissions": {
            "allow": [
                "Read(./**)", "Write(./work/**)", "Edit(./work/**)",
                "Write(./evidence/**)", "Edit(./evidence/**)",
                "Write(./artifacts/**)", "Edit(./artifacts/**)",
                "Write(./CLAUDE_RETURN.json)", "Edit(./CLAUDE_RETURN.json)",
                "Bash(./ctf-tool status)", "Bash(./ctf-tool exec -- *)",
                "Bash(./ctf-tool import-input *)",
            ],
            "deny": [
                "Read(../**)", "Write(./context/**)", "Edit(./context/**)",
                "Write(./RESCUE_PACKET.json)", "Edit(./RESCUE_PACKET.json)",
                "Write(./sandbox.json)", "Edit(./sandbox.json)",
                "Write(./ctf-tool)", "Edit(./ctf-tool)",
                "Bash(git *)", "Bash(docker *)", "Bash(sudo *)", "Bash(ssh *)",
                "Bash(curl *)", "Bash(nc *)", "Bash(ncat *)", "Bash(codex *)",
                "Bash(claude *)", "Bash(python *codex*)", "Bash(python *claude*)",
            ],
        }
    }


def _agent_files() -> dict[str, str]:
    def render(
        name: str, description: str, model: str, tools: Sequence[str],
        disallowed: Sequence[str], max_turns: int, body: str,
    ) -> str:
        tool_values = ", ".join(tools)
        denied = ", ".join(disallowed)
        return (
            "---\n"
            f"name: {name}\n"
            f"description: {description}\n"
            f"model: {model}\n"
            f"tools: [{tool_values}]\n"
            f"disallowedTools: [{denied}]\n"
            f"maxTurns: {max_turns}\n"
            "---\n\n" + body.strip() + "\n"
        )
    common_denied = ["WebFetch", "WebSearch"]
    return {
        "ctf-recon-haiku.md": render(
            "ctf-recon-haiku",
            "Use for one bounded objective reconnaissance question when missing facts block a decisive experiment.",
            "haiku", ["Read", "Grep", "Glob", "Bash"], common_denied + ["Write", "Edit"], 6,
            "Inspect only generated context or imported input. Use ctf-tool for commands. Return the smallest fact that changes the exploit decision.",
        ),
        "clean-room-recon-haiku.md": render(
            "clean-room-recon-haiku",
            "Use in deep profile to independently reinterpret evidence without assuming the Codex leading hypothesis is correct.",
            "haiku", ["Read", "Grep", "Glob", "Bash"], common_denied + ["Write", "Edit"], 7,
            "Build at most two mechanism hypotheses from evidence, explicitly ignoring the leading path as an answer. Propose the cheapest separating test.",
        ),
        "evidence-triage-haiku.md": render(
            "evidence-triage-haiku",
            "Use when claims need compression and classification before the main solver chooses an experiment.",
            "haiku", ["Read", "Grep", "Glob"], common_denied + ["Write", "Edit", "Bash"], 5,
            "Classify every claim as CONFIRMED, CANDIDATE, REFUTED, or UNTESTED and cite its exact receipt or evidence path. Never upgrade narrative.",
        ),
        "exploit-builder-sonnet.md": render(
            "exploit-builder-sonnet",
            "Use after a plausible primitive exists and an executable PoC or solver artifact is the shortest route forward.",
            "sonnet", ["Read", "Grep", "Glob", "Write", "Edit", "Bash"], common_denied, 12,
            "Write only under work, evidence, or artifacts. Use ctf-tool for all execution and networking. Produce a runnable artifact and exact next argv.",
        ),
        "alternate-solver-sonnet.md": render(
            "alternate-solver-sonnet",
            "Use when the leading family is blocked or refuted and a materially different exploit mechanism needs a bounded implementation attempt.",
            "sonnet", ["Read", "Grep", "Glob", "Write", "Edit", "Bash"], common_denied, 10,
            "Avoid recorded refuted families. Choose a distinct mechanism, run one separating experiment, and implement only if it survives.",
        ),
    }


def _ctf_tool_wrapper(
    repo_root: Path,
    rescue_root: Path,
    packet: Mapping[str, Any],
) -> str:
    return (
        "#!/bin/sh\n"
        "set -eu\n"
        f"exec uv run --project {shlex.quote(str(repo_root))} python -m ctf_os.rescue_tool "
        f"--repo {shlex.quote(str(repo_root))} "
        f"--metadata {shlex.quote(str(rescue_root / 'sandbox.json'))} "
        f"--run-id {shlex.quote(str(packet['identity']['run_id']))} "
        f"--rescue-id {shlex.quote(str(packet['identity']['rescue_attempt_id']))} \"$@\"\n"
    )


def _validate_return_shape(result: Mapping[str, Any]) -> None:
    required = {
        "schema_version", "rescue_attempt_id", "run_id", "challenge_instance_id",
        "input_fingerprint", "target_revision", "packet_digest", "requested_lead_model",
        "observed_lead_model", "runtime_observation_evidence", "fallback_observed",
        "verdict", "summary", "verified_observations", "new_attack_path",
        "decisive_experiments", "artifacts", "remote_ready", "flag_claim",
        "message_for_codex",
    }
    missing = sorted(required.difference(result))
    extra = sorted(set(result).difference(required))
    if missing:
        raise RescueError("CLAUDE_RETURN.json is missing: " + ", ".join(missing))
    if extra:
        raise RescueError("CLAUDE_RETURN.json has unsupported fields: " + ", ".join(extra))
    if result.get("schema_version") != 1:
        raise RescueError("CLAUDE_RETURN.json schema_version must be 1")
    if result.get("verdict") not in VERDICTS:
        raise RescueError("CLAUDE_RETURN.json verdict is unsupported")
    for field in ("summary", "new_attack_path", "message_for_codex"):
        if not isinstance(result.get(field), str):
            raise RescueError(f"CLAUDE_RETURN.json {field} must be a string")
    for field in ("verified_observations", "decisive_experiments", "artifacts"):
        if not isinstance(result.get(field), list):
            raise RescueError(f"CLAUDE_RETURN.json {field} must be an array")


def _validate_model_observation(rescue_root: Path, result: Mapping[str, Any]) -> None:
    observed = result.get("observed_lead_model")
    evidence = result.get("runtime_observation_evidence")
    fallback = result.get("fallback_observed")
    if observed is None:
        if evidence is not None or fallback is not None:
            raise RescueError("unobserved model must not carry runtime or fallback observation")
        return
    if not isinstance(observed, str) or not observed.strip() or not isinstance(evidence, str):
        raise RescueError("observed model requires an actual runtime evidence path")
    path = _safe_rescue_path(
        rescue_root, evidence, "runtime observation evidence",
        allowed={"evidence", "logs"},
    )
    content = _read_bounded_text(path, 256 * 1024)
    if observed.casefold() not in content.casefold():
        raise RescueError("runtime observation evidence does not contain the observed model")
    if fallback not in {None, True, False}:
        raise RescueError("fallback_observed must be boolean or null")


def _validate_return_artifacts(
    rescue_root: Path,
    value: object,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_SELECTED_FILES:
        raise RescueError("return artifacts must be a bounded array")
    rows: list[dict[str, Any]] = []
    for raw in value:
        if not isinstance(raw, Mapping):
            raise RescueError("return artifact rows must be objects")
        unsupported = set(raw).difference({"path", "sha256", "executable", "description"})
        if unsupported:
            raise RescueError(
                "return artifact has unsupported fields: " + ", ".join(sorted(unsupported))
            )
        path_value = raw.get("path")
        digest = raw.get("sha256")
        if not isinstance(path_value, str) or not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise RescueError("return artifact requires path and SHA-256")
        path = _safe_rescue_path(
            rescue_root, path_value, "return artifact", allowed={"artifacts", "work"},
        )
        if _sha256(path) != digest:
            raise RescueError(f"return artifact SHA-256 mismatch: {path_value}")
        executable = bool(path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        if raw.get("executable") is True and not executable:
            raise RescueError(f"return artifact is not executable: {path_value}")
        rows.append({**dict(raw), "absolute_path": str(path), "actual_executable": executable})
    return rows


def _validate_return_evidence(rescue_root: Path, result: Mapping[str, Any]) -> None:
    references: list[str] = []
    for row in result.get("verified_observations", []):
        if not isinstance(row, Mapping):
            raise RescueError("verified observation rows must be objects")
        if isinstance(row.get("evidence"), str):
            references.append(str(row["evidence"]))
    for row in result.get("decisive_experiments", []):
        if not isinstance(row, Mapping):
            raise RescueError("decisive experiment rows must be objects")
        if "argv" in row:
            _direct_argv(row.get("argv"))
        for key in ("evidence", "command_evidence", "output_evidence"):
            if isinstance(row.get(key), str):
                references.append(str(row[key]))
    for reference in references:
        _safe_rescue_path(
            rescue_root, reference, "return evidence",
            allowed={"evidence", "logs", "artifacts", "work"},
        )


def _validate_remote_flag_claim(
    rescue_root: Path,
    packet: Mapping[str, Any],
    challenge: ChallengeSpec,
    result: Mapping[str, Any],
    artifacts: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    claim = result.get("flag_claim")
    if not isinstance(claim, Mapping):
        raise RescueError("REMOTE_FLAG_OBTAINED requires flag_claim")
    required = {
        "candidate", "host", "port", "protocol", "exact_argv",
        "command_evidence", "output_evidence", "exploit_artifact",
    }
    if not required.issubset(claim):
        raise RescueError("REMOTE_FLAG_OBTAINED flag_claim is incomplete")
    unsupported = set(claim).difference(required)
    if unsupported:
        raise RescueError(
            "REMOTE_FLAG_OBTAINED flag_claim has unsupported fields: "
            + ", ".join(sorted(unsupported))
        )
    candidate = str(claim.get("candidate") or "")
    if not candidate or not matches_flag(candidate, challenge.flag_pattern):
        raise RescueError("remote flag candidate does not match the current flag pattern")
    port_raw = claim.get("port")
    if not isinstance(port_raw, int) or isinstance(port_raw, bool):
        raise RescueError("remote flag port must be an integer")
    port = port_raw
    host = str(claim.get("host") or "")
    protocol = str(claim.get("protocol") or "")
    declared = parse_remotes(packet.get("authorized_targets", []))
    matching = [
        target for target in declared
        if target_matches_observation(target, host, port, protocol)
    ]
    if len(matching) != 1:
        raise RescueError("remote flag claim does not match one organizer-declared target")
    argv = _direct_argv(claim.get("exact_argv"))
    command_path = _safe_rescue_path(
        rescue_root, str(claim["command_evidence"]), "command evidence", allowed={"logs"},
    )
    command_row = _matching_command_receipt(command_path, argv)
    if command_row is None:
        raise RescueError("REMOTE_FLAG_OBTAINED has no matching sandbox command receipt")
    if command_row.get("authorized_network_observed") is not True:
        raise RescueError("REMOTE_FLAG_OBTAINED lacks an authorized network observation")
    if candidate not in str(command_row.get("stdout") or ""):
        raise RescueError("REMOTE_FLAG_OBTAINED candidate is absent from command output")
    output_path = _safe_rescue_path(
        rescue_root, str(claim["output_evidence"]), "output evidence",
        allowed={"evidence", "logs"},
    )
    if candidate not in _read_bounded_text(output_path, 512 * 1024):
        raise RescueError("REMOTE_FLAG_OBTAINED candidate is absent from preserved output evidence")
    artifact_value = str(claim["exploit_artifact"])
    artifact_path = _safe_rescue_path(
        rescue_root, artifact_value, "exploit artifact", allowed={"artifacts", "work"},
    )
    if not any(Path(str(row["absolute_path"])) == artifact_path for row in artifacts):
        raise RescueError("REMOTE_FLAG_OBTAINED exploit artifact is missing from hashed artifacts")
    return {
        "candidate": candidate, "host": host, "port": port, "protocol": protocol,
        "exact_argv": argv, "command_evidence": str(claim["command_evidence"]),
        "output_evidence": str(claim["output_evidence"]),
        "exploit_artifact": artifact_value,
        "authorized_network_observed": True,
    }


def _validate_remote_ready(
    packet: Mapping[str, Any],
    result: Mapping[str, Any],
    artifacts: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    ready = result.get("remote_ready")
    if not isinstance(ready, Mapping) or ready.get("value") is not True:
        raise RescueError("REMOTE_READY_HANDOFF requires remote_ready.value true")
    allowed = {
        "value", "exact_next_argv", "target_index", "success_condition",
        "kill_condition", "maximum_remaining_experiments",
    }
    unsupported = set(ready).difference(allowed)
    if unsupported:
        raise RescueError(
            "REMOTE_READY_HANDOFF has unsupported fields: "
            + ", ".join(sorted(unsupported))
        )
    argv = _direct_argv(ready.get("exact_next_argv"))
    maximum = ready.get("maximum_remaining_experiments")
    if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= maximum <= 3:
        raise RescueError("REMOTE_READY_HANDOFF maximum remaining experiments must be 1 through 3")
    success = str(ready.get("success_condition") or "").strip()
    kill = str(ready.get("kill_condition") or "").strip()
    if not success or not kill:
        raise RescueError("REMOTE_READY_HANDOFF requires success and kill conditions")
    targets = packet.get("authorized_targets")
    index = ready.get("target_index")
    if not isinstance(targets, list) or not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(targets):
        raise RescueError("REMOTE_READY_HANDOFF target index is not a current declared target")
    executable = [row for row in artifacts if row.get("actual_executable")]
    if not executable:
        raise RescueError("REMOTE_READY_HANDOFF requires an existing executable artifact")
    if not str(result.get("message_for_codex") or "").strip():
        raise RescueError("REMOTE_READY_HANDOFF requires a message for Codex")
    return {
        "exact_next_argv": argv, "target_index": index,
        "success_condition": success, "kill_condition": kill,
        "maximum_remaining_experiments": maximum,
        "executable_artifact": executable[0].get("path"),
    }


def _render_resume(
    run: Path,
    rescue_root: Path,
    packet: Mapping[str, Any],
    result: Mapping[str, Any],
    validation: Mapping[str, Any],
) -> str:
    verdict = str(result["verdict"])
    ready = validation.get("remote_ready") if isinstance(validation.get("remote_ready"), Mapping) else None
    remote = validation.get("remote_flag") if isinstance(validation.get("remote_flag"), Mapping) else None
    first_argv = (
        list(ready["exact_next_argv"]) if ready else
        list(remote["exact_argv"]) if remote else []
    )
    maximum = int(ready.get("maximum_remaining_experiments", 1)) if ready else 1
    success = str(ready.get("success_condition")) if ready else (
        "candidate appears in authorized remote output" if remote else "claimed breakthrough reproduces"
    )
    kill = str(ready.get("kill_condition")) if ready else (
        "exact receipt or output does not reproduce" if remote else "decisive evidence contradicts the claim"
    )
    command = (
        shlex.quote(str(rescue_root / "ctf-tool")) + " exec -- "
        + " ".join(shlex.quote(item) for item in first_argv)
        if first_argv else "No command supplied; continue the existing Solve path."
    )
    lines = [
        "# Codex resume", "",
        "> Claude output is candidate insight, not confirmed Solve truth. Validate it before adoption.",
        "", f"- Exact run ID: `{run.name}`",
        f"- Rescue ID: `{packet['identity']['rescue_attempt_id']}`",
        f"- Rescue sandbox metadata: `{rescue_root / 'sandbox.json'}`",
        f"- Validated verdict: `{verdict}`",
        f"- Maximum decisive experiments: {maximum}", "",
        "## First validation command", "", "```bash", command, "```", "",
        f"- Success condition: {success}", f"- Kill condition: {kill}", "",
        "Do not exceed one to three decisive experiments. On success, record the applicable existing "
        "`milestone-save`/`working-poc-commit` receipt. On failure, record the exact "
        "`DECISIVE_EXPERIMENT` with `decision=KILL` or `PRIMITIVE_REFUTED`, including the kill condition.",
        "", "## Existing Solve integration", "",
        "A rescue sandbox is not a race child and is not directly eligible for `working-poc-commit`. "
        "After a successful rescue experiment, record its exact command/evidence through `milestone-save`; "
        "if an explicit one-shot working-PoC transition is still needed, reproduce the artifact in the "
        "current native Sol/worker sandbox and use that sandbox's existing `working-poc-commit` command. "
        "Never add the rescue to race lineage or branch projections.",
    ]
    if remote:
        relative_artifact = (rescue_root / str(remote["exploit_artifact"])).relative_to(run).as_posix()
        flag_command = [
            "uv", "run", "python", "-m", "ctf_os.agent_tools", "flag-receipt-save",
            str(packet["identity"]["challenge_key"]), "--contest", str(packet["identity"]["contest"]),
            "--branch", str(packet["identity"]["rescue_attempt_id"]),
            "--host", str(remote["host"]), "--port", str(remote["port"]),
            "--protocol", str(remote["protocol"]), "--network-observed",
            "--output", str(remote["candidate"]), "--candidate", str(remote["candidate"]),
            "--exploit-artifact", relative_artifact, "--", *list(remote["exact_argv"]),
        ]
        lines.extend([
            "", "## Existing protected flag receipt promotion", "",
            "Only after reproducing all existing `flag-receipt-save` requirements, run:",
            "", "```bash", " ".join(shlex.quote(item) for item in flag_command), "```",
            "", "This validation did not create a candidate, milestone, flag receipt, or submission recommendation.",
        ])
    lines.extend(["", "After adoption or refutation, continue the existing Solve and close only this rescue sandbox."])
    return "\n".join(lines) + "\n"


def _matching_command_receipt(path: Path, argv: Sequence[str]) -> dict[str, Any] | None:
    if path.suffix != ".jsonl":
        raise RescueError("command evidence must be the append-only JSONL command receipt")
    rows = read_jsonl_strict(path, "rescue command receipt ledger")
    matching = [
        row for row in rows
        if row.get("event") == "sandbox_exec" and row.get("command") == list(argv)
    ]
    return matching[-1] if matching else None


def _experiment_has_evidence(rescue_root: Path, row: object) -> bool:
    if not isinstance(row, Mapping):
        return False
    for key in ("evidence", "command_evidence", "output_evidence"):
        value = row.get(key)
        if isinstance(value, str):
            try:
                _safe_rescue_path(
                    rescue_root, value, "decisive experiment evidence",
                    allowed={"evidence", "logs", "artifacts", "work"},
                )
                return True
            except RescueError:
                return False
    return False


def _validate_rescue_metadata(
    metadata: Mapping[str, Any],
    packet: Mapping[str, Any],
    rescue_root: Path,
) -> None:
    identity = packet["identity"]
    expected = {
        "run_id": identity["run_id"],
        "rescue_attempt_id": identity["rescue_attempt_id"],
        "session_id": identity["rescue_attempt_id"],
        "parent_session_id": "sol-main", "external_solver": True,
        "solver_family": "claude", "session_kind": "external-rescue",
        "input_fingerprint": identity["input_fingerprint"],
        "target_revision": identity["target_revision"],
        "workspace_mode": "bind",
    }
    for field, value in expected.items():
        if metadata.get(field) != value:
            raise RescueError(f"rescue sandbox metadata {field} mismatch")
    if Path(str(metadata.get("branch_root") or "")).resolve(strict=False) != rescue_root.resolve(strict=False):
        raise RescueError("rescue sandbox branch_root mismatch")
    labels = metadata.get("runtime_labels")
    if not isinstance(labels, Mapping):
        labels = metadata.get("labels")
    required_labels = {
        "ctf-os.run_id": identity["run_id"],
        "ctf-os.rescue_attempt_id": identity["rescue_attempt_id"],
        "ctf-os.session_kind": "external-rescue",
        "ctf-os.external_solver": "true",
        "ctf-os.workspace_mode": "bind",
        "ctf-os.solver_family": "claude",
    }
    if not isinstance(labels, Mapping) or any(labels.get(key) != value for key, value in required_labels.items()):
        raise RescueError("rescue sandbox labels do not match exact run/rescue identity")


def _validate_packet_against_current_run(
    run: Path,
    packet: Mapping[str, Any],
    challenge: ChallengeSpec,
) -> None:
    identity = packet.get("identity")
    if not isinstance(identity, Mapping):
        raise RescueError("rescue packet identity is malformed")
    state = _load_json(run / "STATE.json", "run state")
    expected = {
        "run_id": run.name,
        "challenge_id": challenge.id,
        "challenge_instance_id": identity.get("challenge_instance_id"),
        "input_fingerprint": identity.get("input_fingerprint"),
        "target_revision": identity.get("target_revision"),
    }
    for field, value in expected.items():
        current = run.name if field == "run_id" else state.get(field)
        if current != value or identity.get(field) != value:
            raise RescueError(f"current exact run {field} no longer matches rescue packet")
    revisions = read_jsonl_strict(
        challenge_workspace(run) / "target-revisions.jsonl", "target revision ledger",
    )
    if revisions and revisions[-1].get("target_revision") != identity.get("target_revision"):
        raise RescueError("current target revision changed after rescue preparation")


def _prepare_response(
    run: Path,
    rescue_root: Path,
    packet: Mapping[str, Any],
    metadata: Mapping[str, Any],
    *,
    idempotent: bool,
) -> dict[str, Any]:
    request = packet["request"]
    return {
        "run_id": run.name,
        "rescue_attempt_id": packet["identity"]["rescue_attempt_id"],
        "operation_id": packet["identity"]["operation_id"],
        "mode": request["mode"], "profile": request["profile"],
        "path": str(rescue_root), "packet_digest": packet["packet_digest"],
        "requested_lead_model": request["requested_lead_model"],
        "observed_lead_model": None,
        "start_command": _start_command(rescue_root, str(request["requested_lead_model"])),
        "fallback_command": _fallback_command(rescue_root, str(request["profile"])),
        "codex_resume_instruction": "Claude 구조대 결과를 검증하고 이어서 원격 플래그까지 풀어라.",
        "resume_command": _resume_command(packet),
        "sandbox_metadata": str(metadata.get("metadata_path")),
        "sandbox_state": "READY", "idempotent": idempotent,
        "claude_process_started": False, "automatic_model_fallback": False,
    }


def _start_command(rescue_root: Path, requested_model: str) -> str:
    return f"cd {shlex.quote(str(rescue_root))}\nclaude --model {shlex.quote(requested_model)}"


def _fallback_command(rescue_root: Path, profile: str) -> str | None:
    return (
        f"cd {shlex.quote(str(rescue_root))}\nclaude --model opus"
        if profile == "deep" else None
    )


def _resume_command(packet: Mapping[str, Any]) -> str:
    identity = packet["identity"]
    return (
        "uv run python -m ctf_os.agent_tools rescue-return-validate "
        f"{shlex.quote(str(identity['challenge_key']))} --contest {shlex.quote(str(identity['contest']))} "
        f"--run-id {shlex.quote(str(identity['run_id']))} "
        f"--rescue-id {shlex.quote(str(identity['rescue_attempt_id']))}"
    )


def _return_file_state(rescue_root: Path) -> str:
    path = rescue_root / "CLAUDE_RETURN.json"
    if path.is_symlink() or not path.is_file():
        return "MISSING"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "MALFORMED"
    return "PENDING" if payload == {} else "PRESENT"


def _rescue_root(run: Path, rescue_id: str, *, require_packet: bool = True) -> Path:
    if not _ID.fullmatch(rescue_id) or not rescue_id.startswith("rescue-"):
        raise RescueError("rescue ID is invalid")
    run = run.resolve(strict=False)
    root = safe_under(run / "rescue", Path(rescue_id))
    if root.is_symlink() or not root.is_dir():
        raise RescueError(f"rescue attempt does not exist in run {run.name}: {rescue_id}")
    if root.parent.parent != run:
        raise RescueError("rescue attempt is not exact-run local")
    if require_packet and not (root / "RESCUE_PACKET.json").is_file():
        raise RescueError("rescue packet is missing")
    return root


def _load_packet(rescue_root: Path) -> dict[str, Any]:
    packet = _load_json(
        rescue_root / "RESCUE_PACKET.json", "rescue packet", maximum=MAX_PACKET_BYTES,
    )
    if packet.get("schema_version") != RESCUE_SCHEMA_VERSION:
        raise RescueError("rescue packet schema is unsupported")
    if not isinstance(packet.get("identity"), dict) or not isinstance(packet.get("request"), dict):
        raise RescueError("rescue packet identity or request is malformed")
    return packet


def _load_json(path: Path, label: str, *, maximum: int = 4 * 1024 * 1024) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RescueError(f"{label} is missing or unsafe")
    if path.stat().st_size > maximum:
        raise RescueError(f"{label} exceeds its bounded size")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RescueError(f"{label} is malformed") from exc
    if not isinstance(payload, dict):
        raise RescueError(f"{label} must be a JSON object")
    return payload


def _safe_path(root: Path, value: str, label: str) -> Path:
    path = Path(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise RescueError(f"{label} must be a safe relative path")
    current = root.resolve(strict=False)
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise RescueError(f"{label} path contains a symlink")
    try:
        return safe_under(root, path)
    except ValueError as exc:
        raise RescueError(f"{label} escapes its exact workspace") from exc


def _safe_rescue_path(
    rescue_root: Path,
    value: str,
    label: str,
    *,
    allowed: set[str] | None = None,
) -> Path:
    path = Path(value)
    if allowed is not None and (not path.parts or path.parts[0] not in allowed):
        raise RescueError(f"{label} must stay under one of {sorted(allowed)}")
    resolved = _safe_path(rescue_root, value, label)
    if resolved.is_symlink() or not resolved.is_file():
        raise RescueError(f"{label} is missing, a symlink, or a special file")
    return resolved


def _direct_argv(value: object) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 256:
        raise RescueError("command receipt requires a non-empty direct argv array")
    forbidden = {";", "&&", "||", "|", ">", ">>", "<", "&"}
    result = [str(item) for item in value]
    if any(
        not item or item in forbidden or any(character in item for character in "\0\r\n")
        for item in result
    ):
        raise RescueError("command argv contains a shell operator or invalid value")
    return result


def _relative_strings(value: object, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise RescueError(f"{label} must be an array")
    result: list[str] = []
    for item in value[:200]:
        text = str(item)
        _safe_path(Path("/tmp/ctf-os-relative-root"), text, label)
        result.append(Path(text).as_posix())
    return result


def _bound_packet(packet: dict[str, Any]) -> None:
    """Deterministically trim only optional context arrays until bounded."""

    order: list[list[Any]] = [
        packet["truth"]["untested"], packet["truth"]["candidates"],
        packet["truth"]["refuted"], packet["decisive_experiments"],
        packet["evidence"], packet["artifacts"], packet["truth"]["confirmed"],
    ]
    packet["context_limits"]["truncated_items"] = 0
    while len(_pretty_json_bytes(packet)) > MAX_PACKET_BYTES:
        target = next((items for items in order if items), None)
        if target is None:
            break
        target.pop()
        packet["context_limits"]["truncated_items"] += 1


def _source_inventory(run: Path) -> list[dict[str, Any]]:
    """Inventory exact-run inputs in their required precedence without importing prose."""

    sources = (
        ("RUN_MANIFEST.json", "authoritative run identity", "json"),
        ("STATE.json", "projection and operational view", "json"),
        ("SOLVE-LAUNCH.json", "authoritative launch receipt", "json"),
        ("milestone-receipts.jsonl", "authoritative typed milestones", "jsonl"),
        ("RACE_LINEAGE.jsonl", "authoritative race lineage", "jsonl"),
        ("candidates.json", "candidate projection", "json"),
        ("control-actions.jsonl", "operational control view", "jsonl"),
        ("race-events.jsonl", "auxiliary generic events only", "jsonl"),
    )
    rows: list[dict[str, Any]] = []
    for priority, (name, role, kind) in enumerate(sources, 1):
        path = run / name
        if not path.exists():
            rows.append({
                "priority": priority, "path": name, "role": role,
                "present": False, "record_count": 0,
            })
            continue
        if path.is_symlink() or not path.is_file():
            raise RescueError(f"exact-run source is missing or unsafe: {name}")
        size = path.stat().st_size
        if size > 16 * 1024 * 1024:
            raise RescueError(f"exact-run source exceeds bounded inventory size: {name}")
        if kind == "json":
            _load_json(path, name, maximum=16 * 1024 * 1024)
            count = 1
        else:
            count = len(read_jsonl_strict(path, name))
        rows.append({
            "priority": priority, "path": name, "role": role,
            "present": True, "record_count": count, "size": size,
            "sha256": _sha256(path),
        })
    receipts = run / "flag-receipts"
    receipt_rows: list[dict[str, Any]] = []
    if receipts.exists():
        if receipts.is_symlink() or not receipts.is_dir():
            raise RescueError("verified receipt directory is unsafe")
        for path in sorted(receipts.glob("*.json")):
            if path.is_symlink() or not path.is_file():
                raise RescueError("verified receipt path is unsafe")
            _load_json(path, "verified receipt")
            receipt_rows.append({
                "path": path.relative_to(run).as_posix(),
                "size": path.stat().st_size, "sha256": _sha256(path),
            })
    rows.insert(5, {
        "priority": 6, "path": "flag-receipts/*.json",
        "role": "authoritative verified flag/submission receipts",
        "present": bool(receipt_rows), "record_count": len(receipt_rows),
        "receipts": receipt_rows,
    })
    for index, row in enumerate(rows, 1):
        row["priority"] = index
    return rows


def _model_policy(profile: str) -> dict[str, Any]:
    return {
        "profile": profile,
        "lead_role": "strategy/reinterpretation" if profile == "deep" else "main solver",
        "maximum_concurrent_haiku": 2,
        "maximum_sonnet_implementation": 1,
        "maximum_initial_subagent_invocations": 3,
        "maximum_active_hypotheses": 2,
        "maximum_initial_decisive_experiments": 3,
        "subagent_nesting_assumed": False,
        "requested_model_is_observed_model": False,
        "automatic_opus_fallback": False,
        "subagents": (
            ["clean-room-recon-haiku", "evidence-triage-haiku", "alternate-solver-sonnet", "exploit-builder-sonnet"]
            if profile == "deep" else
            ["ctf-recon-haiku", "evidence-triage-haiku", "exploit-builder-sonnet", "alternate-solver-sonnet"]
        ),
    }


def _bounded_targets(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise RescueError("preflight authorized targets are malformed")
    rows: list[dict[str, Any]] = []
    allowed = {
        "declared", "host", "port", "scheme", "protocol", "transport",
        "organizer_declared", "callback",
    }
    for row in value[:32]:
        if not isinstance(row, Mapping):
            raise RescueError("preflight authorized target row is malformed")
        rows.append({key: row.get(key) for key in allowed if key in row})
    return rows


def _enum(
    value: str,
    allowed: frozenset[str],
    field: str,
    *,
    preserve_case: bool = False,
) -> str:
    normalized = str(value).strip() if preserve_case else str(value).strip().upper()
    if normalized not in allowed:
        raise RescueError(f"{field} must be one of {sorted(allowed)}")
    return normalized


def _identifier(value: object, field: str) -> str:
    text = str(value or "")
    if not _ID.fullmatch(text):
        raise RescueError(f"{field} is invalid")
    return text


def _text(value: object, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise RescueError(f"{field} must be a string")
    text = value.strip()
    if not text or len(text.encode("utf-8")) > maximum or any(char in text for char in "\0\r\n"):
        raise RescueError(f"{field} is blank, multiline, or exceeds {maximum} bytes")
    return text


def _bounded(value: str, maximum: int) -> str:
    data = value.replace("\x00", "\\0").encode("utf-8")
    if len(data) <= maximum:
        return value.replace("\x00", "\\0")
    return data[: maximum - 3].decode("utf-8", errors="ignore") + "..."


def _producer_session(reference: str) -> str | None:
    parts = Path(reference).parts
    if len(parts) >= 2 and parts[0] == "workers":
        return parts[1]
    return "sol-main"


def _is_text_file(path: Path) -> bool:
    try:
        sample = path.open("rb").read(8192)
    except OSError as exc:
        raise RescueError(f"cannot read referenced context: {path}") from exc
    return b"\x00" not in sample and (
        not sample or len(sample.decode("utf-8", errors="ignore")) >= len(sample) * 0.8
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _copy_file(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise RescueError(f"selected source is unsafe: {source}")
    with source.open("rb") as input_handle, destination.open("xb") as output_handle:
        shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)
        output_handle.flush()
        os.fsync(output_handle.fileno())


def _read_resource(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RescueError(f"Claude rescue resource is missing or unsafe: {path}")
    return path.read_text(encoding="utf-8").rstrip() + "\n"


def _read_bounded_text(path: Path, maximum: int) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise RescueError(f"bounded text evidence is missing, unsafe, or exceeds {maximum} bytes")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise RescueError("text evidence is not valid UTF-8") from exc


def _pretty_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
