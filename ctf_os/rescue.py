"""Exact-run, manually launched Claude rescue workspaces.

This module prepares data, sandboxes, and receipts.  It never launches or
supervises a model process.  Preparation/return validation never promote state;
only the explicit Sol-only exact-receipt promotion enters the protected flag path.
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
import subprocess
from typing import Any, Iterator

from .contest import ChallengeSpec, ContestManifest
from .flags import matches_flag
from .preflight import prepared_tree_fingerprint
from .sandbox.preparation import (
    PreparedSandbox, prepare_sandbox_spec, validate_prepared_input,
)
from .sandbox.runtime import cleanup, create, probe_service_connectivity
from .resources.scheduler import ResourceLedger
from .service import ServiceActor, service_attachment
from .workspace import (
    CURRENT_FINGERPRINT_SCHEME, append_jsonl_fsync, atomic_json, atomic_text,
    challenge_workspace, read_jsonl_strict, safe_under, utc_now,
)


RESCUE_SCHEMA_VERSION = 2
SUPPORTED_RESCUE_SCHEMA_VERSIONS = frozenset({1, 2})
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
PROFILES = frozenset({"standard", "assisted", "deep", "fable-strategy"})
RESEARCH_POLICIES = frozenset({"offline", "public-web", "public-web-and-mcp"})
VERDICTS = frozenset({
    "REMOTE_FLAG_OBTAINED", "REMOTE_READY_HANDOFF", "CONFIRMED_BREAKTHROUGH",
    "NO_NEW_PATH", "ERROR",
})
LEDGER_EVENTS = frozenset({
    "RESCUE_PREPARED", "RESCUE_SANDBOX_READY", "RESCUE_RETURN_VALIDATED",
    "RESCUE_RUNTIME_RECORDED", "RESCUE_COMMAND_RECORDED",
    "RESCUE_HANDED_BACK", "RESCUE_CONFIRMED", "RESCUE_REFUTED",
    "RESCUE_CLOSED", "RESCUE_ERROR",
    "RESCUE_SANDBOX_CREATING", "RESCUE_SANDBOX_MISSING",
    "RESCUE_SANDBOX_RECOVERED", "RESCUE_SANDBOX_RECOVERY_FAILED",
})
IMMUTABLE_STATUSES = frozenset({
    "ACCEPTED", "SEALED", "SEALED_CLEAN", "SOLVED", "SUBMISSION_RECOMMENDED",
    "FULLY_VERIFIED", "TERMINATION_PENDING", "TERMINATED",
})
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
CLAUDE_HOME_ENV = "CTF_OS_CLAUDE_HOME"


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
    research_policy: str | None = None,
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
    normalized_research = _enum(
        research_policy or "offline", RESEARCH_POLICIES, "research_policy",
        preserve_case=True,
    )
    research_policy_source = (
        "operator-declared" if research_policy is not None
        else "default-offline-contest-policy-unavailable"
    )
    normalized_operation = _text(operation_id, "operation_id", 256)
    normalized_objective = _text(objective, "objective", 2000)
    normalized_blocker = _text(current_blocker, "current_blocker", 2000)
    leading = _text(
        leading_exploit_path or normalized_objective,
        "leading_exploit_path", 2000,
    )
    default_models = {
        "standard": "sonnet", "assisted": "sonnet", "deep": "opus",
        "fable-strategy": "claude-fable-5",
    }
    requested_model = _text(
        lead_model or default_models[normalized_profile],
        "lead_model", 160,
    )
    identity = validate_exact_live_mutable_run(run, challenge, record)
    _validate_rescue_base(run)
    validate_prepared_input(
        challenge_workspace(run), record,
        fingerprint_reader=prepared_fingerprint_reader,
    )
    rid = rescue_attempt_id(run.name, normalized_operation)
    rescue_root = _external_rescue_root(manifest, challenge, run, rid)

    truth, experiments, state_summary, references = _truth_from_run(
        run, leading_exploit_path=leading, current_blocker=normalized_blocker,
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
        "research_policy": normalized_research,
        "research_policy_source": research_policy_source,
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
        "research_policy": normalized_research,
        "research_policy_source": research_policy_source,
        "external_research_allowed": normalized_research != "offline",
        "exact_challenge_lookup_policy": "operator-declared",
        "model_policy": _model_policy(normalized_profile),
        "claude_code_capabilities": _claude_code_capabilities(),
        "model_requirements": _model_requirements(requested_model),
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
            _write_rescue_pointer(run, rescue_root, packet)
            _append_event_unlocked(
                run, packet, "RESCUE_PREPARED",
                details={
                    "mode": normalized_mode, "profile": normalized_profile,
                    "requested_lead_model": requested_model,
                    "research_policy": normalized_research,
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
        "session_role": "external-rescue",
        "require_running_managed_service": managed,
        "workspace_mode": "bind",
        "run_id": run.name,
        "rescue_attempt_id": rid,
        "external_solver": True,
        "solver_family": "claude",
        "session_kind": "external-rescue",
        "requested_lead_model": requested_model,
        "allow_scheduler_rebalance": False,
        "prepared_fingerprint_reader": prepared_fingerprint_reader,
    }
    if service_inspector is not None:
        prepare_kwargs["service_inspector"] = service_inspector
    metadata: dict[str, object] | None = None
    resource_requested = False
    try:
        prepared = sandbox_preparer(**prepare_kwargs)
        ResourceLedger(run).request(
            prepared.spec.resource_request,
            actor_session_id="sol-main", actor_role="sol",
            inference={
                "source": "manual-claude-rescue",
                "workload_class": "external-rescue",
                "automatic_rebalance": False,
            },
        )
        resource_requested = True
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
            with rescue_lock(run):
                _append_event_unlocked(
                    run, packet, "RESCUE_SANDBOX_CREATING",
                    details={"container": prepared.spec.name, "phase": "initial-create"},
                )
            metadata = sandbox_factory(prepared.spec)
            metadata["packet_digest"] = packet["packet_digest"]
            metadata["source_repo_path"] = str(repo_root.resolve(strict=False))
            metadata["source_run_path"] = str(run.resolve(strict=False))
            metadata_path = Path(str(metadata.get("metadata_path") or rescue_root / "sandbox.json"))
            atomic_json(metadata_path, metadata)
            _lock_read_only_workspace(rescue_root)
            _validate_rescue_metadata(metadata, packet, rescue_root)
            if prepared.spec.service_network:
                metadata["connectivity_probe"] = connectivity_probe(metadata)
                atomic_json(Path(str(metadata["metadata_path"])), metadata)
            if metadata.get("actual_image_id") and metadata.get("image"):
                from .rescue_backend import RescueBackend
                RescueBackend(run, rescue_root, metadata, packet).inventory(refresh=True)
    except Exception as exc:
        cleanup_error = None
        if metadata is not None:
            try:
                sandbox_cleanup(
                    metadata, session_id=rid, session_role="external-rescue",
                )
            except Exception as cleanup_exc:
                cleanup_error = str(cleanup_exc)[:2000]
        if resource_requested:
            try:
                ResourceLedger(run).release(
                    rid, "rescue sandbox preparation failed",
                    actor_session_id="sol-main", actor_role="sol",
                )
            except Exception as release_exc:
                cleanup_error = cleanup_error or str(release_exc)[:2000]
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
    from .rescue_backend import record_telemetry
    record_telemetry(rescue_root, "sandbox_ready", details={
        "container": metadata.get("name"),
        "sandbox_image_id": metadata.get("actual_image_id"),
    })
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
    runtime_state = "MISSING"
    recovery_state = "RECOVERY_REQUIRED"
    if metadata is not None:
        try:
            inspected = subprocess.run(
                ["docker", "inspect", str(metadata.get("name") or "")],
                capture_output=True, text=True, timeout=30, check=False,
            )
            if inspected.returncode == 0:
                try:
                    runtime = json.loads(inspected.stdout)[0]
                    runtime_state = "RUNNING" if runtime.get("State", {}).get("Running") is True else "STOPPED"
                except (json.JSONDecodeError, IndexError, TypeError):
                    runtime_state = "ERROR"
            image = subprocess.run(
                ["docker", "image", "inspect", str(metadata.get("image") or ""), "--format", "{{.Id}}"],
                capture_output=True, text=True, timeout=30, check=False,
            )
            image_matches = image.returncode == 0 and (
                not metadata.get("actual_image_id")
                or image.stdout.strip() == metadata.get("actual_image_id")
            )
            service_matches = True
            if metadata.get("service_network"):
                service_matches = subprocess.run(
                    ["docker", "network", "inspect", str(metadata["service_network"])],
                    capture_output=True, text=True, timeout=30, check=False,
                ).returncode == 0
            recovery_state = "RECOVERABLE" if image_matches and service_matches else "RECOVERY_REQUIRED"
        except (OSError, subprocess.TimeoutExpired):
            runtime_state, recovery_state = "MISSING", "RECOVERY_REQUIRED"
    projected_sandbox_state = (
        runtime_state if runtime_state == "RUNNING"
        else recovery_state if runtime_state in {"MISSING", "STOPPED"}
        else runtime_state
    )
    latest = None
    if metadata is not None:
        from .rescue_backend import RescueBackend
        from .rescue_hooks import latest_session
        latest = latest_session(RescueBackend(run, rescue_root, metadata, packet))
    request = packet["request"]
    claude_session_id = latest.get("session_id") if latest else None
    return {
        "rescue_attempt_id": rescue_id,
        "operation_id": packet["identity"]["operation_id"],
        "run_id": run.name,
        "attempt_id": packet["identity"]["attempt_id"],
        "challenge_instance_id": packet["identity"]["challenge_instance_id"],
        "mode": request["mode"], "profile": request["profile"],
        "status": state["status"],
        "requested_lead_model": request["requested_lead_model"],
        "research_policy": packet.get("research_policy", "offline"),
        "observed_lead_model": latest.get("model") if latest else state.get("observed_lead_model"),
        "claude_session_id": claude_session_id,
        "runtime_observation_evidence": state.get("runtime_observation_evidence"),
        "fallback_observed": state.get("fallback_observed"),
        "packet_digest": packet["packet_digest"],
        "ctf_tool_digest": state.get("ctf_tool_digest"),
        "sandbox_state": projected_sandbox_state,
        "sandbox_runtime_state": runtime_state,
        "sandbox_recovery_state": recovery_state,
        "return_file_state": _return_file_state(rescue_root),
        "start_command": _start_command(rescue_root, str(request["requested_lead_model"])),
        "fallback_command": _fallback_command(rescue_root, str(request["profile"])),
        "resume_command": _resume_command(packet, run),
        "claude_resume_command": (
            f"claude --resume '{str(claude_session_id)}'"
            if claude_session_id else None
        ),
        "claude_continue_command": "claude --continue",
        "validation_state": state["validation_state"],
        "path": str(rescue_root),
        "process_state_inferred": False,
    }


def record_rescue_runtime(
    run: Path,
    rescue_id: str,
    *,
    observed_model: str,
    evidence: str,
    fallback_observed: bool | None = None,
) -> dict[str, Any]:
    """Record operator-observed model identity without inferring process state."""

    rescue_root = _rescue_root(run, rescue_id)
    packet = _load_packet(rescue_root)
    _validate_packet_against_current_run(run, packet, None)
    observed = _text(observed_model, "observed_model", 160)
    evidence_path = _safe_rescue_path(
        rescue_root, evidence, "runtime observation evidence",
        allowed={"evidence", "logs"},
    )
    if evidence_path.stat().st_size > MAX_SELECTED_TEXT_BYTES:
        raise RescueError("runtime observation evidence exceeds the bounded text limit")
    evidence_text = _read_bounded_text(evidence_path, MAX_SELECTED_TEXT_BYTES)
    if observed.casefold() not in evidence_text.casefold():
        raise RescueError("runtime observation evidence does not contain the observed model")
    requested = str(packet["request"]["requested_lead_model"])
    if fallback_observed not in {None, True, False}:
        raise RescueError("fallback_observed must be boolean or null")
    if fallback_observed is not None and "fallback" not in evidence_text.casefold():
        raise RescueError("fallback observation requires explicit fallback evidence")
    details = {
        "requested_lead_model": requested,
        "observed_lead_model": observed,
        "runtime_observation_evidence": evidence_path.relative_to(rescue_root).as_posix(),
        "runtime_observation_evidence_sha256": _sha256(evidence_path),
        "fallback_observed": fallback_observed,
    }
    with rescue_lock(run):
        row = _append_event_unlocked(
            run, packet, "RESCUE_RUNTIME_RECORDED", details=details,
        )
    return {
        "run_id": run.name, "rescue_attempt_id": rescue_id,
        "packet_digest": packet["packet_digest"], **details,
        "event_id": row["event_id"],
    }


def record_rescue_command(
    run: Path,
    rescue_id: str,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind one ctf-tool receipt to the append-only rescue lifecycle ledger."""

    rescue_root = _rescue_root(run, rescue_id)
    packet = _load_packet(rescue_root)
    required = {
        "command_receipt_id", "run_id", "rescue_attempt_id", "packet_digest",
        "command_digest", "stdout_digest", "stderr_digest", "evidence_path",
    }
    if not required.issubset(receipt):
        raise RescueError("rescue command receipt is incomplete")
    if (
        receipt.get("run_id") != run.name
        or receipt.get("rescue_attempt_id") != rescue_id
        or receipt.get("packet_digest") != packet.get("packet_digest")
    ):
        raise RescueError("rescue command receipt identity mismatch")
    evidence_path = _safe_rescue_path(
        rescue_root, str(receipt["evidence_path"]), "command output evidence",
        allowed={"evidence"},
    )
    if receipt.get("evidence_digest") != _sha256(evidence_path):
        raise RescueError("rescue command output evidence digest mismatch")
    details = {
        "command_receipt_id": receipt["command_receipt_id"],
        "command_digest": receipt["command_digest"],
        "authorized_network_observed": receipt.get("authorized_network_observed") is True,
        "evidence_path": receipt["evidence_path"],
        "evidence_digest": receipt["evidence_digest"],
    }
    with rescue_lock(run):
        return _append_event_unlocked(
            run, packet, "RESCUE_COMMAND_RECORDED", details=details,
        )


def validate_rescue_return(
    run: Path,
    challenge: ChallengeSpec,
    rescue_id: str,
) -> dict[str, Any]:
    """Validate candidate insight and write only rescue-local handback files."""

    rescue_root = _rescue_root(run, rescue_id)
    from .rescue_backend import record_telemetry
    record_telemetry(rescue_root, "codex_resumed", details={"operation": "rescue-return-validate"})
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
    _validate_model_observation(run, rescue_root, result)

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
    record_telemetry(rescue_root, "return_validated", details={
        "verdict": verdict, "return_digest": return_digest,
    })
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


def promote_rescue_flag(
    run: Path, challenge: ChallengeSpec, rescue_id: str, *,
    execution_receipt_id: str, candidate: str, exploit_artifact: str,
) -> dict[str, Any]:
    """Promote only preserved exact-rescue execution evidence into the protected path."""

    from .sandbox.network import parse_remotes
    from .verification import record_remote_flag
    rescue_root = _rescue_root(run, rescue_id)
    packet = _load_packet(rescue_root)
    _validate_packet_against_current_run(run, packet, challenge)
    if not matches_flag(candidate, challenge.flag_pattern):
        raise RescueError("rescue flag promotion candidate does not match the current flag pattern")
    receipt = _execution_receipt_by_id(rescue_root, execution_receipt_id)
    identity = packet["identity"]
    if (
        receipt.get("run_id") != run.name
        or receipt.get("rescue_attempt_id") != rescue_id
        or receipt.get("packet_digest") != packet.get("packet_digest")
        or receipt.get("authorized_network_observed") is not True
    ):
        raise RescueError("execution receipt identity or network proof is invalid")
    evidence = _safe_rescue_path(
        rescue_root, str(receipt.get("evidence_path") or ""),
        "execution output evidence", allowed={"evidence"},
    )
    evidence_digest = _sha256(evidence)
    if evidence_digest != receipt.get("evidence_digest"):
        raise RescueError("execution output evidence digest mismatch")
    output_bytes = evidence.read_bytes()
    if candidate.encode() not in output_bytes:
        raise RescueError("candidate is absent from preserved execution output")
    source_artifact = _safe_rescue_path(
        rescue_root, exploit_artifact, "rescue exploit artifact",
        allowed={"work", "artifacts"},
    )
    artifact_digest = _sha256(source_artifact)
    snapshots = receipt.get("artifact_snapshot")
    if isinstance(snapshots, Mapping):
        after = snapshots.get("after") if isinstance(snapshots.get("after"), Mapping) else snapshots
        files = after.get("files") if isinstance(after, Mapping) else None
        if isinstance(files, list) and not any(
            isinstance(row, Mapping)
            and row.get("path") == exploit_artifact
            and row.get("sha256") == artifact_digest
            for row in files
        ):
            raise RescueError("execution receipt artifact snapshot does not bind the exploit artifact")
    observed_rows = [
        row for row in list(receipt.get("network_observation") or [])
        if isinstance(row, Mapping) and row.get("observed") is True
    ]
    if len(observed_rows) != 1:
        # Schema-v1 command receipt compatibility.
        indices = list(receipt.get("authorized_network_target_indices") or [])
        targets = list(receipt.get("authorized_targets") or [])
        if len(indices) != 1 or not isinstance(indices[0], int) or not 0 <= indices[0] < len(targets):
            raise RescueError("execution receipt lacks one exact observed target")
        observed = targets[indices[0]]
    else:
        observed = observed_rows[0]
    if not isinstance(observed, Mapping):
        raise RescueError("execution receipt observed target is malformed")
    destination = run / "artifacts" / "claude-rescue" / rescue_id / source_artifact.name
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if destination.is_symlink() or not destination.is_file() or _sha256(destination) != artifact_digest:
            raise RescueError("promoted exploit artifact path conflicts with existing content")
    else:
        _copy_file(source_artifact, destination)
        destination.chmod(source_artifact.stat().st_mode & 0o777)
    argv = _direct_argv(receipt.get("argv"))
    result = record_remote_flag(
        run, challenge_id=challenge.id,
        input_fingerprint=str(identity["input_fingerprint"]), branch_id=rescue_id,
        declared_targets=parse_remotes(challenge.remotes),
        observed_host=str(observed.get("host") or observed.get("resolved_ip") or observed.get("ip") or ""),
        observed_port=int(observed.get("port") or 0),
        observed_protocol=str(observed.get("transport") or observed.get("protocol") or ""),
        network_observed=True,
        output=output_bytes.decode("utf-8", errors="replace"), candidate=candidate,
        flag_pattern=challenge.flag_pattern, command_argv=argv,
        exploit_artifact=destination.relative_to(run).as_posix(),
        target_revision=int(identity["target_revision"]),
        receipt_metadata={
            "source_type": "CLAUDE_RESCUE", "rescue_attempt_id": rescue_id,
            "packet_digest": packet["packet_digest"],
            "execution_receipt_id": execution_receipt_id,
            "sandbox_image_id": receipt.get("sandbox_image_id"),
            "output_evidence_digest": evidence_digest,
        },
    )
    from .rescue_backend import record_telemetry
    record_telemetry(rescue_root, "flag_receipt_created", details={
        "execution_receipt_id": execution_receipt_id,
        "receipt_path": result.get("receipt"),
    })
    return result


def close_rescue(
    run: Path,
    rescue_id: str,
    *,
    outcome: str | None = None,
    evidence_receipt_id: str | None = None,
    reason: str | None = None,
    sandbox_cleanup: Callable[..., dict[str, object]] = cleanup,
) -> dict[str, Any]:
    selected_outcome = outcome if outcome is not None else reason
    if selected_outcome is None:
        raise RescueError("rescue close requires an outcome")
    normalized = _enum(
        selected_outcome,
        frozenset({"integrated", "refuted", "no-new-path", "flag-obtained", "manual"}),
        "outcome", preserve_case=True,
    )
    evidence_id = (
        _text(evidence_receipt_id, "evidence_receipt_id", 256)
        if evidence_receipt_id is not None else None
    )
    if normalized in {"integrated", "flag-obtained"} and evidence_id is None:
        raise RescueError(f"{normalized} rescue close requires an evidence receipt ID")
    rescue_root = _rescue_root(run, rescue_id)
    packet = _load_packet(rescue_root)
    if evidence_id is not None and not _existing_receipt_id(
        run, rescue_root, evidence_id,
    ):
        raise RescueError("rescue close evidence receipt does not exist in this exact run")
    state = project_rescue_state(run, rescue_id)
    if state.get("status") == "CLOSED":
        return {
            "run_id": run.name, "rescue_attempt_id": rescue_id,
            "closed": True, "outcome": state.get("close_outcome"), "idempotent": True,
            "workspace_preserved": True,
        }
    metadata_path = rescue_root / "sandbox.json"
    closed_sessions: list[dict[str, Any]] = []
    if metadata_path.is_file() and not metadata_path.is_symlink():
        metadata = _load_json(metadata_path, "rescue sandbox metadata")
        _validate_rescue_metadata(metadata, packet, rescue_root)
        from .rescue_sessions import RescueSessionManager
        closed_sessions = RescueSessionManager(
            run, rescue_root, metadata, packet,
        ).close_all()
        runtime = subprocess.run(
            ["docker", "inspect", str(metadata.get("name") or "")],
            capture_output=True, text=True, timeout=30, check=False,
        )
        cleanup_receipt = (
            {"sandbox_cleanup": "NOT_PRESENT", "container": metadata.get("name")}
            if runtime.returncode and sandbox_cleanup is cleanup else
            sandbox_cleanup(
                metadata, session_id=rescue_id, session_role="external-rescue",
            )
        )
    else:
        cleanup_receipt = {"sandbox_cleanup": "NOT_PRESENT"}
    try:
        ResourceLedger(run).release(
            rescue_id, "manual Claude rescue closed",
            actor_session_id="sol-main", actor_role="sol",
        )
    except Exception as exc:
        cleanup_receipt = {**cleanup_receipt, "resource_release_warning": str(exc)[:1000]}
    with rescue_lock(run):
        if normalized in {"integrated", "flag-obtained"}:
            _append_event_unlocked(
                run, packet, "RESCUE_CONFIRMED",
                details={"outcome": normalized, "evidence_receipt_id": evidence_id},
            )
        elif normalized in {"refuted", "no-new-path"}:
            _append_event_unlocked(
                run, packet, "RESCUE_REFUTED",
                details={"outcome": normalized, "evidence_receipt_id": evidence_id},
            )
        _append_event_unlocked(
            run, packet, "RESCUE_CLOSED",
            details={
                "outcome": normalized, "evidence_receipt_id": evidence_id,
                "cleanup_receipt": cleanup_receipt,
                "closed_persistent_sessions": len(closed_sessions),
            },
        )
    from .rescue_backend import record_telemetry
    record_telemetry(rescue_root, "rescue_closed", details={
        "outcome": normalized, "evidence_receipt_id": evidence_id,
    })
    return {
        "run_id": run.name, "rescue_attempt_id": rescue_id,
        "closed": True, "outcome": normalized,
        "cleanup_receipt": cleanup_receipt, "idempotent": False,
        "closed_persistent_sessions": len(closed_sessions),
        "workspace_preserved": True,
    }


def load_rescue_ledger(run: Path) -> list[dict[str, Any]]:
    _validate_rescue_base(run)
    rows = read_jsonl_strict(
        run / "rescue" / "RESCUE_LEDGER.jsonl", "rescue ledger",
    )
    for row in rows:
        required = {
            "schema_version", "event_id", "event", "rescue_attempt_id",
            "operation_id", "run_id", "challenge_instance_id",
            "input_fingerprint", "target_revision", "packet_digest",
            "details", "created_at",
        }
        if (
            not required.issubset(row)
            or row.get("schema_version") != RESCUE_LEDGER_SCHEMA_VERSION
            or row.get("event") not in LEDGER_EVENTS
            or not isinstance(row.get("details"), dict)
            or row.get("run_id") != run.name
            or not isinstance(row.get("target_revision"), int)
            or not _SHA256.fullmatch(str(row.get("packet_digest") or ""))
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
    close_outcome = None
    for row in rows:
        event = row["event"]
        details = row["details"]
        if event == "RESCUE_SANDBOX_READY":
            status, sandbox_state = "READY", "READY"
        elif event == "RESCUE_SANDBOX_CREATING":
            sandbox_state = "RECOVERY_REQUIRED"
        elif event == "RESCUE_SANDBOX_MISSING":
            sandbox_state = "MISSING"
        elif event == "RESCUE_SANDBOX_RECOVERED":
            status, sandbox_state = "READY", "READY"
        elif event == "RESCUE_SANDBOX_RECOVERY_FAILED":
            sandbox_state = "RECOVERY_REQUIRED"
        elif event == "RESCUE_RUNTIME_RECORDED":
            observed_model = details.get("observed_lead_model")
            runtime_evidence = details.get("runtime_observation_evidence")
            fallback_observed = details.get("fallback_observed")
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
            close_outcome = details.get("outcome") or details.get("reason")
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
        "close_outcome": close_outcome,
        "last_event_id": rows[-1].get("event_id"),
        "last_event": rows[-1].get("event"),
        "event_count": len(rows),
        "packet_digest": packet.get("packet_digest") if packet else None,
        "ctf_tool_digest": (
            _sha256(rescue_root / "ctf-tool")
            if (rescue_root / "ctf-tool").is_file()
            and not (rescue_root / "ctf-tool").is_symlink() else None
        ),
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
    repeatable = {
        "RESCUE_ERROR", "RESCUE_COMMAND_RECORDED", "RESCUE_RUNTIME_RECORDED",
        "RESCUE_SANDBOX_CREATING", "RESCUE_SANDBOX_MISSING",
        "RESCUE_SANDBOX_RECOVERED", "RESCUE_SANDBOX_RECOVERY_FAILED",
    }
    same_event = next((
        row for row in rows
        if row.get("rescue_attempt_id") == identity["rescue_attempt_id"]
        and row.get("event") == event
    ), None)
    if same_event is not None and event not in repeatable:
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
    current_blocker: str,
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]], dict[str, Any], list[tuple[str, str]]]:
    truth: dict[str, list[dict[str, Any]]] = {
        "confirmed": [], "candidates": [], "refuted": [], "untested": [],
    }
    references: list[tuple[str, str]] = []
    experiments: list[dict[str, Any]] = []
    rows = read_jsonl_strict(
        run / "milestone-receipts.jsonl", "milestone receipt ledger",
    )
    milestone_ids = {
        str(row.get("receipt_id")) for row in rows if row.get("receipt_id")
    }
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
        detail = row.get("details") if isinstance(row.get("details"), Mapping) else {}
        control_reference = (
            detail.get("negative_control_assertion_receipt")
            or detail.get("control_receipt")
        )
        controlled = isinstance(control_reference, str) and (
            control_reference in milestone_ids
            or control_reference in evidence
            or control_reference in artifacts
        )
        if event == "PRIMITIVE_CONFIRMED" and linked and controlled:
            claim["truth_level"] = "CONFIRMED"
            claim["positive_assertion_receipt"] = row.get("receipt_id")
            claim["control_receipt"] = control_reference
            truth["confirmed"].append(claim)
        elif event == "WORKING_POC" and (artifacts or row.get("command_digest")):
            claim["truth_level"] = "CONFIRMED"
            truth["confirmed"].append(claim)
            working_poc = True
        elif event in {"PRIMITIVE_CANDIDATE", "FLAG_CANDIDATE"} or (
            event == "PRIMITIVE_CONFIRMED" and not (linked and controlled)
        ):
            claim["truth_level"] = "CANDIDATE"
            truth["candidates"].append(claim)
        elif event == "PRIMITIVE_REFUTED":
            claim["truth_level"] = "REFUTED"
            truth["refuted"].append(claim)
        elif event == "DECISIVE_EXPERIMENT":
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
    truth["candidates"].append({
        "truth_level": "CANDIDATE", "source": "operator_request",
        "summary": _bounded(leading_exploit_path, 2000),
        "operator_provided": True,
    })
    truth["candidates"].append({
        "truth_level": "CANDIDATE", "source": "operator_request",
        "summary": _bounded(current_blocker, 2000),
        "claim_kind": "current_blocker", "operator_provided": True,
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
        ".claude/agents", "context/selected", "sessions",
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
        "rescue-memory.json": {
            "objective": packet["request"]["objective"],
            "current_blocker": packet["request"]["current_blocker"],
            "leading_path": packet["request"]["leading_exploit_path"],
            "confirmed": packet["truth"]["confirmed"],
            "candidates": packet["truth"]["candidates"],
            "refuted": packet["truth"]["refuted"],
            "untested": packet["truth"]["untested"],
            "active_hypotheses": [],
            "last_decisive_experiment": (
                packet["decisive_experiments"][-1]
                if packet["decisive_experiments"] else None
            ),
            "working_poc": packet["state"]["working_poc"],
            "remote_state": {
                "remote_ready": packet["state"]["remote_ready"],
                "remote_attempted": packet["state"]["remote_attempted"],
                "flag_candidate": packet["state"]["flag_candidate"],
            },
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
    profile_text = _read_resource(
        resources / "profiles" / f"{packet['request']['profile']}.md"
    )
    identity_note = (
        f"\n## Exact assignment\n\n- Run: `{run.name}`\n"
        f"- Rescue: `{packet['identity']['rescue_attempt_id']}`\n"
        f"- Packet digest: `{packet['packet_digest']}`\n"
        f"- Mode/profile: `{packet['request']['mode']}` / `{packet['request']['profile']}`\n"
    )
    atomic_text(
        rescue_root / "CLAUDE.md",
        base + identity_note + "\n" + profile_text + "\n" + mode_text + "\n"
        + _read_resource(playbook_path),
    )
    atomic_text(rescue_root / "REQUEST.md", _render_request(packet))
    atomic_text(rescue_root / "MODEL_POLICY.md", _render_model_policy(packet))
    atomic_text(rescue_root / "START.md", _render_start(rescue_root, packet))
    shutil.copyfile(resources / "RETURN.schema.json", rescue_root / "RETURN.schema.json")
    (rescue_root / "RETURN.schema.json").chmod(0o444)
    shutil.copyfile(resources / "RETURN.example.json", rescue_root / "RETURN.example.json")
    (rescue_root / "RETURN.example.json").chmod(0o444)
    atomic_json(rescue_root / "CLAUDE_RETURN.json", {})
    atomic_text(
        rescue_root / "CODEX-RESUME.md",
        "# Codex resume\n\nPending `rescue-return-validate`. Claude output is not confirmed Solve truth.\n",
    )
    atomic_json(rescue_root / ".claude" / "settings.json", _claude_settings(packet))
    for name in _agent_file_names(str(packet["request"]["profile"])):
        source = resources / "agents" / name
        destination = rescue_root / ".claude" / "agents" / name
        shutil.copyfile(source, destination)
        destination.chmod(0o444)
    for ledger in (
        "RESCUE_COMMANDS.jsonl", "RESCUE_SESSIONS.jsonl", "RESCUE_PROGRESS.jsonl",
        "RESCUE_TASKS.jsonl", "KNOWLEDGE_SOURCES.jsonl", "KNOWLEDGE_HINTS.jsonl",
        "CLAUDE_SESSION_EVENTS.jsonl", "RESCUE_TELEMETRY.jsonl",
    ):
        atomic_text(rescue_root / ledger, "")
        (rescue_root / ledger).chmod(0o600)
    atomic_json(rescue_root / "RESCUE_LIVE_STATE.json", {
        "schema_version": 1, "run_id": run.name,
        "rescue_attempt_id": packet["identity"]["rescue_attempt_id"],
        "packet_digest": packet["packet_digest"], "active_hypotheses": [],
        "current_blocker": packet["request"]["current_blocker"],
        "last_decisive_experiment": None, "latest_working_artifact": None,
        "next_action": None, "event_count": 0,
    })
    atomic_json(rescue_root / "TOOLCHAIN_RECEIPT.json", {
        "schema_version": 1, "status": "PENDING_SANDBOX_INVENTORY",
        "run_id": run.name, "rescue_attempt_id": packet["identity"]["rescue_attempt_id"],
        "packet_digest": packet["packet_digest"],
    })
    wrapper = _ctf_tool_wrapper(repo_root, rescue_root, packet)
    atomic_text(rescue_root / "ctf-tool", wrapper)
    (rescue_root / "ctf-tool").chmod(0o555)
    atomic_json(rescue_root / ".mcp.json", {
        "mcpServers": {
            "ctf-rescue": {
                "type": "stdio", "command": str(rescue_root / "ctf-tool"),
                "args": ["mcp-serve"], "env": {},
            }
        }
    })
    for name in (
        "CLAUDE.md", "REQUEST.md", "MODEL_POLICY.md", "START.md",
        "RESCUE_PACKET.json", "RETURN.schema.json", "RETURN.example.json",
    ):
        (rescue_root / name).chmod(0o444)
    (rescue_root / ".claude" / "settings.json").chmod(0o444)
    (rescue_root / "CLAUDE_RETURN.json").chmod(0o600)
    (rescue_root / "CODEX-RESUME.md").chmod(0o600)
    (rescue_root / ".mcp.json").chmod(0o444)
    from .rescue_backend import record_telemetry
    record_telemetry(rescue_root, "rescue_prepared", details={
        "requested_model": packet["request"]["requested_lead_model"],
        "profile": packet["request"]["profile"],
    })


def _lock_read_only_workspace(rescue_root: Path) -> None:
    for base_name in ("context", ".claude"):
        base = rescue_root / base_name
        if base.is_symlink() or not base.is_dir():
            raise RescueError(f"rescue read-only tree is missing or unsafe: {base_name}")
        paths = sorted(base.rglob("*"), key=lambda path: len(path.parts), reverse=True)
        for path in paths:
            if path.is_symlink():
                raise RescueError(f"rescue read-only tree contains a symlink: {path}")
            if path.is_dir():
                path.chmod(0o555)
            elif path.is_file():
                path.chmod(0o444)
            else:
                raise RescueError(f"rescue read-only tree contains a special file: {path}")
        base.chmod(0o555)


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
        "- Record authoritative observed model only from the Claude Code SessionStart hook; legacy runtime evidence is fallback-only.",
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
    requirements = packet.get("model_requirements", {})
    capabilities = packet.get("claude_code_capabilities", {})
    lines = [
        "# Manual start", "",
        "CTF-OS did not start Claude. Pause or exit Codex, open a new terminal, and run:",
        "", "```bash", start, "```", "",
        f"- Requested model: `{packet['request']['requested_lead_model']}`",
        "- Observed model: `PENDING SessionStart hook`",
        f"- Cyber routing/fallback: {requirements.get('cyber_routing_or_fallback', 'not configured')}",
        f"- Retention requirement: {requirements.get('retention_requirement', 'account policy applies')}",
        f"- Account requirement: {requirements.get('account_requirement', 'model access required')}",
        f"- Research policy: `{packet.get('research_policy', 'offline')}`",
        f"- Research policy source: `{packet.get('research_policy_source', 'schema-v1/default-offline')}`",
        f"- Claude Code installed during preparation: `{capabilities.get('installed', False)}`",
        f"- Claude Code version observed during preparation: `{capabilities.get('version') or 'UNAVAILABLE'}`",
        "- Runtime hook evidence, not the requested alias, is authoritative for the observed model.",
        "", "## Installed Claude Code capability probe", "",
    ]
    for feature, observation in dict(capabilities.get("features") or {}).items():
        installed = observation.get("installed_observed") if isinstance(observation, Mapping) else None
        state = "SUPPORTED" if installed is True else (
            "UNAVAILABLE (CLI not installed or option absent)" if installed is False
            else "OFFICIALLY DOCUMENTED; installed CLI help cannot prove this project/runtime feature"
        )
        lines.append(f"- `{feature}`: {state}")
    if packet["request"]["profile"] == "fable-strategy":
        lines.extend([
            "", "Fable is a strategy profile. It may produce a cyber classifier refusal. "
            "CTF-OS does not automatically restart or route the model; end the session and let the operator "
            "choose a separate Sonnet/Opus execution session.",
        ])
    lines.extend([
        "", "Once SessionStart has recorded a session ID, `rescue-show` prints `claude --resume '<session-id>'`. ",
        "`claude --continue` remains a directory-local fallback; prefer the explicit session ID.",
    ])
    return "\n".join(lines) + "\n"


def _claude_settings(packet: Mapping[str, Any]) -> dict[str, Any]:
    research = str(packet.get("research_policy") or "offline")
    allow = [
        "Read(./**)", "Write(./work/**)", "Edit(./work/**)",
        "Write(./evidence/**)", "Edit(./evidence/**)",
        "Write(./artifacts/**)", "Edit(./artifacts/**)",
        "Write(./CLAUDE_RETURN.json)", "Edit(./CLAUDE_RETURN.json)",
        "Bash(./ctf-tool *)", "mcp__ctf-rescue__*",
    ]
    if research in {"public-web", "public-web-and-mcp"}:
        allow.extend(["WebSearch", "WebFetch"])
    if research == "public-web-and-mcp":
        allow.append("mcp__*")
    hook_events = (
        "SessionStart", "PreCompact", "PostCompact", "SessionEnd",
        "SubagentStart", "SubagentStop", "TaskCreated", "TaskCompleted",
    )
    hooks = {
        event: [{
            "hooks": [{
                "type": "command", "command": f"./ctf-tool hook {event}",
                "timeout": 10,
            }],
        }]
        for event in hook_events
    }
    hooks["PreToolUse"] = [{
        "hooks": [{
            "type": "command", "command": "./ctf-tool hook PreToolUse", "timeout": 10,
        }],
    }]
    hooks["PostToolUse"] = [{
        "matcher": "WebSearch|WebFetch|mcp__.*", "hooks": [{
            "type": "command", "command": "./ctf-tool hook PostToolUse", "timeout": 10,
        }],
    }]
    deny = [
        "Read(../**)", "Write(./context/**)", "Edit(./context/**)",
        "Write(./RESCUE_PACKET.json)", "Edit(./RESCUE_PACKET.json)",
        "Write(./sandbox.json)", "Edit(./sandbox.json)",
        "Write(./ctf-tool)", "Edit(./ctf-tool)",
        "Bash(git *)", "Bash(docker *)", "Bash(sudo *)", "Bash(ssh *)",
        "Bash(curl *)", "Bash(wget *)", "Bash(nc *)", "Bash(ncat *)", "Bash(codex *)",
        "Bash(claude *)", "Bash(python *codex*)", "Bash(python *claude*)",
    ]
    if research == "offline":
        deny.extend(["WebSearch", "WebFetch"])
    features = packet.get("claude_code_capabilities", {}).get("features", {})
    dont_ask = isinstance(features, Mapping) and isinstance(features.get("dontAsk"), Mapping) and features["dontAsk"].get("installed_observed") is True
    return {
        "permissions": {
            "defaultMode": "dontAsk" if dont_ask else "default",
            "allow": allow, "deny": deny,
        },
        "hooks": hooks,
    }


def _agent_file_names(profile: str) -> tuple[str, ...]:
    if profile == "standard":
        return ()
    if profile == "assisted":
        return (
            "ctf-recon-haiku.md", "evidence-triage-haiku.md",
            "exploit-builder-sonnet.md", "alternate-solver-sonnet.md",
        )
    if profile == "deep":
        return (
            "ctf-recon-haiku.md", "evidence-triage-haiku.md",
            "alternate-solver-sonnet.md", "exploit-builder-sonnet.md",
        )
    return (
        "clean-room-recon-haiku.md", "alternate-solver-sonnet.md",
        "exploit-builder-sonnet.md",
    )


def _ctf_tool_wrapper(
    repo_root: Path,
    rescue_root: Path,
    packet: Mapping[str, Any],
) -> str:
    runtime_root = _claude_runtime_root()
    return (
        "#!/bin/sh\n"
        "set -eu\n"
        f"export CTF_OS_RESCUE_REPO={shlex.quote(str(repo_root))}\n"
        f"export CTF_OS_RESCUE_METADATA={shlex.quote(str(rescue_root / 'sandbox.json'))}\n"
        f"export CTF_OS_RESCUE_RUN_ID={shlex.quote(str(packet['identity']['run_id']))}\n"
        f"export CTF_OS_RESCUE_ID={shlex.quote(str(packet['identity']['rescue_attempt_id']))}\n"
        f"export CTF_OS_RESCUE_PACKET_DIGEST={shlex.quote(str(packet['packet_digest']))}\n"
        "command=${1:-}\n"
        "case \"$command\" in\n"
        "  status|exec|import-input|inventory|session|progress|task|knowledge|sandbox|hook|mcp-serve) ;;\n"
        "  *) echo 'unsupported exact-rescue ctf-tool command' >&2; exit 2 ;;\n"
        "esac\n"
        f"exec uv run --project {shlex.quote(str(runtime_root))} python -m ctf_os.rescue_tool "
        f"--repo {shlex.quote(str(repo_root))} "
        f"--metadata {shlex.quote(str(rescue_root / 'sandbox.json'))} "
        f"--run-id {shlex.quote(str(packet['identity']['run_id']))} "
        f"--rescue-id {shlex.quote(str(packet['identity']['rescue_attempt_id']))} "
        f"--packet-digest {shlex.quote(str(packet['packet_digest']))} \"$@\"\n"
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


def _validate_model_observation(
    run: Path, rescue_root: Path, result: Mapping[str, Any],
) -> None:
    observed = result.get("observed_lead_model")
    evidence = result.get("runtime_observation_evidence")
    fallback = result.get("fallback_observed")
    rescue_id = rescue_root.name
    recorded = [
        row for row in load_rescue_ledger(run)
        if row.get("rescue_attempt_id") == rescue_id
        and row.get("event") == "RESCUE_RUNTIME_RECORDED"
    ]
    hook_path = rescue_root / "CLAUDE_SESSION_EVENTS.jsonl"
    hook_rows = read_jsonl_strict(hook_path, "Claude session event ledger") if hook_path.is_file() else []
    hook_starts = [row for row in hook_rows if row.get("event") == "SessionStart" and row.get("model")]
    if hook_starts:
        authoritative = hook_starts[-1]
        if observed != authoritative.get("model"):
            raise RescueError("observed model does not match authoritative SessionStart hook evidence")
        if evidence != "CLAUDE_SESSION_EVENTS.jsonl":
            raise RescueError("hook-observed model must reference CLAUDE_SESSION_EVENTS.jsonl")
        if fallback not in {None, True, False}:
            raise RescueError("fallback_observed must be boolean or null")
        return
    if observed is None:
        if evidence is not None or fallback is not None:
            raise RescueError("unobserved model must not carry runtime or fallback observation")
        if recorded:
            raise RescueError("Claude return omits the recorded runtime model observation")
        return
    if not isinstance(observed, str) or not observed.strip() or not isinstance(evidence, str):
        raise RescueError("observed model requires an actual runtime evidence path")
    path = _safe_rescue_path(
        rescue_root, evidence, "runtime observation evidence",
        allowed={"evidence", "logs", "CLAUDE_SESSION_EVENTS.jsonl"},
    )
    content = _read_bounded_text(path, 256 * 1024)
    if observed.casefold() not in content.casefold():
        raise RescueError("runtime observation evidence does not contain the observed model")
    if fallback not in {None, True, False}:
        raise RescueError("fallback_observed must be boolean or null")
    matches = [
        row for row in recorded
        if row.get("details", {}).get("observed_lead_model") == observed
        and row.get("details", {}).get("runtime_observation_evidence") == evidence
        and row.get("details", {}).get("fallback_observed") == fallback
    ]
    if not matches:
        raise RescueError(
            "observed model requires a matching rescue-runtime-record receipt"
        )


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
        if isinstance(row.get("command_receipt_id"), str):
            _command_receipt_by_id(rescue_root, str(row["command_receipt_id"]))
        if isinstance(row.get("session_observation_receipt_id"), str):
            _session_receipt_by_id(
                rescue_root, str(row["session_observation_receipt_id"]),
            )
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
    required = {"candidate", "exploit_artifact"}
    receipt_fields = [
        key for key in ("execution_receipt_id", "command_receipt_id")
        if claim.get(key)
    ]
    if not required.issubset(claim) or len(receipt_fields) != 1:
        raise RescueError("REMOTE_FLAG_OBTAINED flag_claim is incomplete")
    unsupported = set(claim).difference(required | {"execution_receipt_id", "command_receipt_id"})
    if unsupported:
        raise RescueError(
            "REMOTE_FLAG_OBTAINED flag_claim has unsupported fields: "
            + ", ".join(sorted(unsupported))
        )
    candidate = str(claim.get("candidate") or "")
    if not candidate or not matches_flag(candidate, challenge.flag_pattern):
        raise RescueError("remote flag candidate does not match the current flag pattern")
    execution_id = str(claim.get(receipt_fields[0]) or "")
    command_row = _execution_receipt_by_id(rescue_root, execution_id)
    if command_row.get("authorized_network_observed") is not True:
        raise RescueError("REMOTE_FLAG_OBTAINED lacks an authorized network observation")
    if command_row.get("packet_digest") != packet.get("packet_digest"):
        raise RescueError("REMOTE_FLAG_OBTAINED command receipt packet digest mismatch")
    if (
        command_row.get("run_id") != packet["identity"]["run_id"]
        or command_row.get("rescue_attempt_id") != packet["identity"]["rescue_attempt_id"]
    ):
        raise RescueError("REMOTE_FLAG_OBTAINED command receipt belongs to another rescue")
    indices = command_row.get("authorized_network_target_indices")
    receipt_targets = command_row.get("authorized_targets")
    if (
        not isinstance(indices, list) or not indices
        or any(not isinstance(index, int) for index in indices)
        or not isinstance(receipt_targets, list)
    ):
        raise RescueError("REMOTE_FLAG_OBTAINED lacks an exact declared target observation")
    targets = packet.get("authorized_targets")
    if not isinstance(targets, list):
        raise RescueError("REMOTE_FLAG_OBTAINED declared targets are malformed")
    observed_targets: list[Mapping[str, Any]] = []
    for index in indices:
        if not 0 <= index < len(receipt_targets) or not isinstance(receipt_targets[index], Mapping):
            raise RescueError("REMOTE_FLAG_OBTAINED declared target mismatch")
        observed_targets.append(receipt_targets[index])
    matching_indices = {
        packet_index
        for packet_index, declared_target in enumerate(targets)
        if isinstance(declared_target, Mapping)
        and all(_same_declared_target(declared_target, observed) for observed in observed_targets)
    }
    if len(matching_indices) != 1:
        raise RescueError("REMOTE_FLAG_OBTAINED declared target mismatch")
    target_index = matching_indices.pop()
    target = targets[target_index]
    if not isinstance(target, Mapping):
        raise RescueError("REMOTE_FLAG_OBTAINED declared target is malformed")
    argv = _direct_argv(command_row.get("argv"))
    output_path = _safe_rescue_path(
        rescue_root, str(command_row.get("evidence_path") or ""), "output evidence",
        allowed={"evidence"},
    )
    if candidate.encode() not in output_path.read_bytes()[: 512 * 1024]:
        raise RescueError("REMOTE_FLAG_OBTAINED candidate is absent from preserved output evidence")
    artifact_value = str(claim["exploit_artifact"])
    artifact_path = _safe_rescue_path(
        rescue_root, artifact_value, "exploit artifact", allowed={"artifacts", "work"},
    )
    if not any(Path(str(row["absolute_path"])) == artifact_path for row in artifacts):
        raise RescueError("REMOTE_FLAG_OBTAINED exploit artifact is missing from hashed artifacts")
    return {
        "candidate": candidate, "host": str(target.get("host") or ""),
        "port": int(target.get("port") or 0),
        "protocol": str(target.get("protocol") or target.get("transport") or ""),
        "target_index": target_index,
        "exact_argv": argv, "execution_receipt_id": execution_id,
        "command_receipt_id": command_row.get("command_receipt_id"),
        "session_observation_receipt_id": command_row.get("observation_receipt_id"),
        "command_evidence": (
            "RESCUE_SESSIONS.jsonl" if command_row.get("observation_receipt_id")
            else "RESCUE_COMMANDS.jsonl"
        ),
        "output_evidence": str(command_row["evidence_path"]),
        "exploit_artifact": artifact_value,
        "authorized_network_observed": True,
    }


def _same_declared_target(
    declared: Mapping[str, Any], observed: Mapping[str, Any],
) -> bool:
    declared_protocol = str(
        declared.get("protocol") or declared.get("transport") or ""
    ).casefold()
    observed_protocols = {
        str(observed.get("protocol") or "").casefold(),
        str(observed.get("transport") or "").casefold(),
    }
    declared_transport = str(
        declared.get("transport") or declared_protocol
    ).casefold()
    observed_transport = str(
        observed.get("transport") or declared_transport
    ).casefold()
    return (
        str(declared.get("host") or "").casefold().rstrip(".")
        == str(observed.get("host") or "").casefold().rstrip(".")
        and declared.get("port") == observed.get("port")
        and declared_protocol in observed_protocols
        and declared_transport == observed_transport
    )


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
        "kill_condition", "maximum_remaining_experiments", "exploit_artifact",
        "exploit_artifact_sha256",
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
    artifact_value = str(ready.get("exploit_artifact") or "")
    matching_artifacts = [
        row for row in artifacts
        if row.get("path") == artifact_value
    ]
    artifact_digest = str(ready.get("exploit_artifact_sha256") or "")
    if (
        not artifact_value or len(matching_artifacts) != 1
        or matching_artifacts[0].get("sha256") != artifact_digest
    ):
        raise RescueError("REMOTE_READY_HANDOFF requires a matching hashed exploit artifact")
    container_artifact = "/" + artifact_value
    interpreter_link = len(argv) > 1 and argv[1] == container_artifact
    executable_link = argv[0] == container_artifact and matching_artifacts[0].get("actual_executable")
    if not (interpreter_link or executable_link):
        raise RescueError("REMOTE_READY_HANDOFF argv is not linked to the exploit artifact")
    if not str(result.get("message_for_codex") or "").strip():
        raise RescueError("REMOTE_READY_HANDOFF requires a message for Codex")
    return {
        "exact_next_argv": argv, "target_index": index,
        "success_condition": success, "kill_condition": kill,
        "maximum_remaining_experiments": maximum,
        "executable_artifact": artifact_value,
        "exploit_artifact_sha256": artifact_digest,
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
        f"- Packet digest: `{packet['packet_digest']}`",
        f"- Rescue sandbox metadata: `{rescue_root / 'sandbox.json'}`",
        f"- Validated verdict: `{verdict}`",
        "- Validated artifacts: " + (
            ", ".join(f"`{row.get('path')}`" for row in result.get("artifacts", []))
            or "none"
        ),
        "- Validated command receipts: " + (
            f"`{remote['execution_receipt_id']}`" if remote else
            ", ".join(
                f"`{row.get('command_receipt_id')}`"
                for row in result.get("decisive_experiments", [])
                if isinstance(row, Mapping) and row.get("command_receipt_id")
            ) or "none"
        ),
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
        flag_command = [
            "uv", "run", "python", "-m", "ctf_os.agent_tools", "rescue-flag-promote",
            str(packet["identity"]["challenge_key"]), "--contest", str(packet["identity"]["contest"]),
            "--run-id", str(packet["identity"]["run_id"]),
            "--rescue-id", str(packet["identity"]["rescue_attempt_id"]),
            "--execution-receipt-id", str(remote["execution_receipt_id"]),
            "--candidate", str(remote["candidate"]),
            "--exploit-artifact", str(remote["exploit_artifact"]),
        ]
        lines.extend([
            "", "## Exact-run protected flag receipt promotion", "",
            f"Validated execution receipt: `{remote['execution_receipt_id']}`  ",
            f"Preserved output: `{remote['output_evidence']}`  ",
            f"Observed target: `{remote['host']}:{remote['port']}/{remote['protocol']}`  ",
            f"Network observation proof: `{remote['command_evidence']}#{remote['execution_receipt_id']}`",
            "",
            "Only from the resumed Sol/Codex path, run:",
            "", "```bash", " ".join(shlex.quote(item) for item in flag_command), "```",
            "", "This validation did not create a candidate, milestone, flag receipt, or submission recommendation.",
        ])
    lines.extend(["", "After adoption or refutation, continue the existing Solve and close only this rescue sandbox."])
    return "\n".join(lines) + "\n"


def _command_receipt_by_id(rescue_root: Path, receipt_id: str) -> dict[str, Any]:
    if not receipt_id or not _ID.fullmatch(receipt_id):
        raise RescueError("command receipt ID is missing or malformed")
    rows = read_jsonl_strict(
        rescue_root / "RESCUE_COMMANDS.jsonl", "rescue command receipt ledger",
    )
    matching = [row for row in rows if row.get("command_receipt_id") == receipt_id]
    if len(matching) != 1:
        raise RescueError("REMOTE_FLAG_OBTAINED has no unique matching command receipt")
    row = matching[0]
    required = {
        "schema_version", "command_receipt_id", "run_id", "rescue_attempt_id",
        "packet_digest", "argv", "command_digest", "stdout_digest",
        "stderr_digest", "authorized_network_observed", "evidence_path",
        "evidence_digest",
    }
    if row.get("schema_version") != 1 or not required.issubset(row):
        raise RescueError("rescue command receipt is malformed")
    evidence_path = _safe_rescue_path(
        rescue_root, str(row["evidence_path"]), "command output evidence",
        allowed={"evidence"},
    )
    if _sha256(evidence_path) != row.get("evidence_digest"):
        raise RescueError("rescue command output evidence digest mismatch")
    return row


def _session_receipt_by_id(rescue_root: Path, receipt_id: str) -> dict[str, Any]:
    if not receipt_id or not _ID.fullmatch(receipt_id):
        raise RescueError("session observation receipt ID is missing or malformed")
    path = rescue_root / "RESCUE_SESSIONS.jsonl"
    rows = read_jsonl_strict(path, "rescue session receipt ledger") if path.is_file() else []
    matching = [
        row for row in rows
        if row.get("event") == "SESSION_OUTPUT_OBSERVED"
        and receipt_id in {row.get("observation_receipt_id"), row.get("receipt_id")}
    ]
    if len(matching) != 1:
        raise RescueError("REMOTE_FLAG_OBTAINED has no unique session observation receipt")
    row = matching[0]
    required = {
        "run_id", "rescue_attempt_id", "packet_digest", "session_id",
        "session_kind", "cursor_before", "cursor_after", "output_digest",
        "evidence_path", "evidence_digest", "authorized_network_observed",
    }
    if not required.issubset(row):
        raise RescueError("rescue session observation receipt is malformed")
    evidence = _safe_rescue_path(
        rescue_root, str(row["evidence_path"]), "session output evidence",
        allowed={"evidence"},
    )
    if _sha256(evidence) != row.get("evidence_digest"):
        raise RescueError("rescue session output evidence digest mismatch")
    return row


def _execution_receipt_by_id(rescue_root: Path, receipt_id: str) -> dict[str, Any]:
    command_error = None
    try:
        return _command_receipt_by_id(rescue_root, receipt_id)
    except RescueError as exc:
        command_error = exc
    try:
        return _session_receipt_by_id(rescue_root, receipt_id)
    except RescueError as session_error:
        raise RescueError("no unique command or session observation receipt") from session_error


def _existing_receipt_id(run: Path, rescue_root: Path, receipt_id: str) -> bool:
    for ledger_name in ("milestone-receipts.jsonl", "RESCUE_COMMANDS.jsonl", "RESCUE_SESSIONS.jsonl"):
        path = (
            rescue_root / ledger_name
            if ledger_name in {"RESCUE_COMMANDS.jsonl", "RESCUE_SESSIONS.jsonl"} else run / ledger_name
        )
        for row in read_jsonl_strict(path, ledger_name):
            if receipt_id in {
                row.get("receipt_id"), row.get("command_receipt_id"), row.get("event_id"),
                row.get("observation_receipt_id"),
            }:
                return True
    for directory in (
        run / "flag-receipts", run / "working-poc-operations",
        run / "working-poc-resolution-receipts",
    ):
        if not directory.exists():
            continue
        if directory.is_symlink() or not directory.is_dir():
            raise RescueError("exact-run receipt directory is unsafe")
        for path in directory.glob("*.json"):
            if path.is_symlink() or not path.is_file():
                raise RescueError("exact-run receipt path is unsafe")
            if _load_json(path, "exact-run receipt").get("receipt_id") == receipt_id:
                return True
    return False


def _experiment_has_evidence(rescue_root: Path, row: object) -> bool:
    if not isinstance(row, Mapping):
        return False
    receipt_id = row.get("command_receipt_id") or row.get("session_observation_receipt_id")
    if isinstance(receipt_id, str):
        try:
            receipt = _execution_receipt_by_id(rescue_root, receipt_id)
        except RescueError:
            return False
        decision = str(row.get("decision") or "").upper()
        observed = str(row.get("observed_result") or "").strip()
        return (
            (receipt.get("exit_code") == 0 or receipt.get("event") == "SESSION_OUTPUT_OBSERVED")
            and bool(observed)
            and decision in {"PROMOTE", "CONFIRMED", "CONTINUE", "SUCCESS"}
        )
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
    challenge: ChallengeSpec | None,
) -> None:
    identity = packet.get("identity")
    if not isinstance(identity, Mapping):
        raise RescueError("rescue packet identity is malformed")
    state = _load_json(run / "STATE.json", "run state")
    manifest = _load_json(run / "RUN_MANIFEST.json", "run manifest")
    manifest_identity = manifest.get("identity")
    manifest_challenge = manifest.get("challenge")
    repository = manifest.get("repository")
    if not all(isinstance(value, Mapping) for value in (
        manifest_identity, manifest_challenge, repository,
    )):
        raise RescueError("current exact run manifest identity is malformed")
    expected = {
        "run_id": run.name,
        "challenge_id": challenge.id if challenge is not None else identity.get("challenge_id"),
        "challenge_instance_id": state.get("challenge_instance_id"),
        "attempt_id": state.get("attempt_id"),
        "input_fingerprint": state.get("input_fingerprint"),
        "fingerprint_scheme": state.get("fingerprint_scheme"),
        "target_revision": state.get("target_revision"),
        "challenge_snapshot_digest": (
            state.get("challenge_snapshot_digest")
            or manifest.get("challenge_snapshot_digest")
        ),
        "transformation_seed": str(state.get("transformation_seed", "NONE")),
        "solve_mode": str(state.get("solve_mode") or manifest.get("mode") or ""),
        "repository_commit": repository.get("commit_sha"),
    }
    for field, value in expected.items():
        current = run.name if field == "run_id" else state.get(field)
        if field in {"challenge_snapshot_digest", "repository_commit"}:
            current = value
        elif field in {"transformation_seed", "solve_mode"}:
            current = str(value)
        if current != value or identity.get(field) != value:
            raise RescueError(f"current exact run {field} no longer matches rescue packet")
    if (
        manifest_identity.get("run_id") != identity.get("run_id")
        or manifest_identity.get("attempt_id") != identity.get("attempt_id")
        or manifest_identity.get("challenge_instance_id") != identity.get("challenge_instance_id")
        or manifest_challenge.get("challenge_id") != identity.get("challenge_id")
        or manifest_challenge.get("input_fingerprint") != identity.get("input_fingerprint")
        or manifest_challenge.get("target_revision") != identity.get("target_revision")
    ):
        raise RescueError("current exact run manifest no longer matches rescue packet")
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
        "resume_command": _resume_command(packet, run),
        "sandbox_metadata": str(metadata.get("metadata_path")),
        "sandbox_state": "READY", "idempotent": idempotent,
        "claude_process_started": False, "automatic_model_fallback": False,
    }


def _start_command(rescue_root: Path, requested_model: str) -> str:
    return f"cd {shlex.quote(str(rescue_root))}\nclaude --model {shlex.quote(requested_model)}"


def _fallback_command(rescue_root: Path, profile: str) -> str | None:
    return (
        f"cd {shlex.quote(str(rescue_root))}\nclaude --model opus"
        if profile == "fable-strategy" else None
    )


def _resume_command(packet: Mapping[str, Any], run: Path) -> str:
    identity = packet["identity"]
    source_repo = _source_repo_root(run)
    return (
        f"uv run --project {shlex.quote(str(source_repo))} "
        "python -m ctf_os.agent_tools "
        f"--repo {shlex.quote(str(source_repo))} rescue-return-validate "
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
    pointer_path = safe_under(
        run / "rescue" / "RESCUE_POINTERS", Path(f"{rescue_id}.json"),
    )
    if pointer_path.is_file() and not pointer_path.is_symlink():
        pointer = _load_json(pointer_path, "rescue pointer", maximum=16 * 1024)
        if pointer.get("run_id") != run.name or pointer.get("rescue_attempt_id") != rescue_id:
            raise RescueError("rescue pointer identity mismatch")
        root = Path(str(pointer.get("path") or "")).resolve(strict=False)
        try:
            root.relative_to((_claude_runtime_root() / "runs").resolve(strict=False))
        except ValueError as exc:
            raise RescueError("rescue pointer escapes the Claude runtime root") from exc
    else:
        # Workspaces made before the repository split remain readable.
        root = safe_under(run / "rescue", Path(rescue_id))
    if root.is_symlink() or not root.is_dir():
        raise RescueError(f"rescue attempt does not exist in run {run.name}: {rescue_id}")
    if require_packet and not (root / "RESCUE_PACKET.json").is_file():
        raise RescueError("rescue packet is missing")
    return root


def _claude_runtime_root() -> Path:
    configured = os.environ.get(CLAUDE_HOME_ENV)
    raw_root = (
        Path(configured).expanduser() if configured
        else Path(__file__).resolve().parents[1]
    )
    if raw_root.is_symlink():
        raise RescueError(f"Claude runtime root must not be a symlink: {raw_root}")
    root = raw_root.resolve(strict=False)
    if not root.is_dir():
        raise RescueError(f"Claude runtime root is missing or unsafe: {root}")
    return root


def _source_repo_root(run: Path) -> Path:
    for candidate in (run, *run.parents):
        if candidate.name == "output":
            return candidate.parent.resolve(strict=False)
    raise RescueError("exact run is not below a source repository output directory")


def _external_rescue_root(
    manifest: ContestManifest, challenge: ChallengeSpec, run: Path, rescue_id: str,
) -> Path:
    parts = (
        str(manifest.slug), str(challenge.category), str(challenge.id),
        str(run.name), rescue_id,
    )
    if any(not _ID.fullmatch(part) for part in parts):
        raise RescueError("Claude workspace identity contains an unsafe path component")
    return safe_under(_claude_runtime_root() / "runs", Path(*parts))


def _write_rescue_pointer(
    run: Path, rescue_root: Path, packet: Mapping[str, Any],
) -> None:
    pointer_dir = run / "rescue" / "RESCUE_POINTERS"
    if pointer_dir.is_symlink():
        raise RescueError("run-local rescue pointer directory is unsafe")
    pointer_dir.mkdir(parents=True, exist_ok=True)
    pointer = pointer_dir / f"{packet['identity']['rescue_attempt_id']}.json"
    payload = {
        "schema_version": 1,
        "run_id": run.name,
        "rescue_attempt_id": packet["identity"]["rescue_attempt_id"],
        "packet_digest": packet["packet_digest"],
        "path": str(rescue_root.resolve(strict=False)),
        "runtime_root": str(_claude_runtime_root()),
    }
    if pointer.is_file():
        if _load_json(pointer, "rescue pointer", maximum=16 * 1024) != payload:
            raise RescueError("existing rescue pointer conflicts with immutable packet")
        return
    atomic_json(pointer, payload)
    pointer.chmod(0o444)


def _load_packet(rescue_root: Path) -> dict[str, Any]:
    packet = _load_json(
        rescue_root / "RESCUE_PACKET.json", "rescue packet", maximum=MAX_PACKET_BYTES,
    )
    if packet.get("schema_version") not in SUPPORTED_RESCUE_SCHEMA_VERSIONS:
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
    working_rows: list[dict[str, Any]] = []
    working_root = run / "working-poc-operations"
    if working_root.exists():
        if working_root.is_symlink() or not working_root.is_dir():
            raise RescueError("working-PoC receipt directory is unsafe")
        for path in sorted(working_root.glob("*.json")):
            if path.is_symlink() or not path.is_file():
                raise RescueError("working-PoC receipt path is unsafe")
            payload = _load_json(path, "working-PoC receipt")
            if str(payload.get("status") or "").upper() not in {
                "WORKING_POC_RECORDED", "EXECUTION_STARTED", "EXECUTION_COMPLETED",
                "REMOTE_FLAG_OBTAINED", "REMOTE_ATTEMPTED", "NO_FLAG",
            }:
                continue
            working_rows.append({
                "path": path.relative_to(run).as_posix(),
                "size": path.stat().st_size, "sha256": _sha256(path),
                "status": payload.get("status"),
            })
    rows.insert(4, {
        "priority": 5, "path": "working-poc-operations/*.json",
        "role": "authoritative committed working-PoC receipts",
        "present": bool(working_rows), "record_count": len(working_rows),
        "receipts": working_rows,
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
    subagents = {
        "standard": [],
        "assisted": [
            "ctf-recon-haiku", "evidence-triage-haiku",
            "exploit-builder-sonnet", "alternate-solver-sonnet",
        ],
        "deep": [
            "ctf-recon-haiku", "evidence-triage-haiku",
            "alternate-solver-sonnet", "exploit-builder-sonnet",
        ],
        "fable-strategy": [
            "clean-room-recon-haiku", "alternate-solver-sonnet",
            "exploit-builder-sonnet",
        ],
    }[profile]
    return {
        "profile": profile,
        "lead_role": "strategy/reinterpretation" if profile == "fable-strategy" else "main solver",
        "maximum_concurrent_haiku": 0 if profile == "standard" else 2,
        "maximum_sonnet_implementation": 0 if profile == "standard" else 1,
        "maximum_initial_subagent_invocations": 0 if profile == "standard" else 3,
        "maximum_active_hypotheses": 2,
        "maximum_initial_decisive_experiments": 3,
        "subagent_nesting_assumed": False,
        "requested_model_is_observed_model": False,
        "automatic_opus_fallback": False,
        "subagents": subagents,
    }


def _claude_code_capabilities() -> dict[str, Any]:
    """Inspect the CLI without starting a model session."""

    executable = shutil.which("claude")
    names = (
        "--resume", "--continue", "--permission-mode", "dontAsk", "project_agents",
        "project_mcp", "SessionStart", "PreCompact", "PostCompact", "SessionEnd",
        "SubagentStart", "SubagentStop", "TaskCreated", "TaskCompleted",
    )
    result: dict[str, Any] = {
        "executable": executable, "installed": executable is not None,
        "version": None, "features": {},
        "official_contract_checked_at": "2026-07-21",
    }
    help_text = ""
    if executable:
        try:
            version = subprocess.run(
                [executable, "--version"], capture_output=True, text=True,
                timeout=10, check=False,
            )
            help_result = subprocess.run(
                [executable, "--help"], capture_output=True, text=True,
                timeout=10, check=False,
            )
            result["version"] = (version.stdout or version.stderr).strip()[:500] or None
            help_text = help_result.stdout + help_result.stderr
        except (OSError, subprocess.TimeoutExpired) as exc:
            result["inspection_error"] = str(exc)[:1000]
    for name in names:
        if name.startswith("--") or name == "dontAsk":
            observed = name in help_text if executable else False
            basis = "installed --help" if executable else "CLI_NOT_INSTALLED"
        else:
            observed = None
            basis = "official Claude Code documentation; runtime hook evidence required"
        result["features"][name] = {
            "officially_supported": True, "installed_observed": observed,
            "basis": basis,
        }
    return result


def _model_requirements(requested_model: str) -> dict[str, Any]:
    fable = requested_model == "claude-fable-5"
    mythos = "mythos" in requested_model.casefold()
    return {
        "requested_model": requested_model,
        "observed_model_source": "Claude Code SessionStart hook only",
        "cyber_routing_or_fallback": (
            "Fable cyber classifier may refuse; any fallback must be observed at runtime and is not automatic in CTF-OS"
            if fable else "none configured by CTF-OS"
        ),
        "retention_requirement": (
            "30-day retention required; unavailable to zero-data-retention workspaces"
            if fable or mythos else "account/provider policy applies"
        ),
        "account_requirement": (
            "Covered Model access and an eligible retained-data account/workspace"
            if fable or mythos else "Claude Code account with requested model access"
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
