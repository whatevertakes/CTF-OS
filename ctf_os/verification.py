"""Verified remote flag receipts and the human-submission fast path."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any

from .candidates import build_candidate, load_candidates, upsert_candidate_payload
from .evidence import append_evidence
from .flags import matches_flag
from .sandbox.network import Target, target_matches_observation
from .projections import apply_projection, ensure_projection_manifest
from .workspace import (
    append_jsonl_fsync, atomic_json, atomic_text, challenge_workspace, resolve_active_run,
    recover_run_state, safe_under, state_lock, update_run_manifest_timing, utc_now,
)


FLAG_STATES = frozenset({
    "FLAG_CANDIDATE", "LOCAL_FLAG_OBTAINED", "REMOTE_FLAG_OBTAINED",
    "SUBMISSION_RECOMMENDED", "FULLY_VERIFIED", "SUBMITTED_BY_HUMAN",
})
REMOTE_RECEIPT_SCHEMA_VERSION = 2
REMOTE_PROJECTIONS = (
    "candidate_state", "result", "evidence", "timing", "verified_event",
    "scheduler", "compatibility",
)


class FastFlagError(ValueError):
    pass


def record_remote_flag(
    root: Path, *, challenge_id: str, input_fingerprint: str, branch_id: str,
    declared_targets: Sequence[Target], observed_host: str, observed_port: int,
    observed_protocol: str, network_observed: bool, output: str,
    candidate: str, flag_pattern: str | None, command_argv: Sequence[str],
    exploit_artifact: str, target_revision: int | None = None,
    receipt_metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    compatibility_root = root.resolve(strict=False)
    run = resolve_active_run(root, input_fingerprint=input_fingerprint, target_revision=target_revision)
    repair_remote_receipt_projections(run, suppress_errors=True)
    if not network_observed:
        raise FastFlagError("REMOTE_FLAG_OBTAINED requires an actual network observation")
    matches = [
        target for target in declared_targets
        if target_matches_observation(target, observed_host, observed_port, observed_protocol)
    ]
    if len(matches) != 1:
        raise FastFlagError("remote receipt target is not the current challenge's declared target")
    if candidate not in output:
        raise FastFlagError("flag candidate was not present in the preserved command output")
    argv = _argv(command_argv)
    artifact = _relative_artifact(exploit_artifact)
    try:
        artifact_path = safe_under(run, Path(artifact))
    except ValueError as exc:
        raise FastFlagError("exploit artifact is unsafe or escapes the run workspace") from exc
    if not artifact_path.is_file():
        try:
            legacy_artifact = safe_under(compatibility_root, Path(artifact))
        except ValueError as exc:
            raise FastFlagError("legacy exploit artifact is unsafe or escapes the challenge workspace") from exc
        if run == compatibility_root or not legacy_artifact.is_file():
            raise FastFlagError("remote flag receipt requires an existing exploit artifact")
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_copy_artifact(legacy_artifact, artifact_path)
    pattern_match = matches_flag(candidate, flag_pattern)
    placeholder = _looks_placeholder(candidate)
    confidence = "HIGH" if pattern_match and not placeholder else "LOW"
    state_name = "SUBMISSION_RECOMMENDED" if confidence == "HIGH" else "FLAG_CANDIDATE"
    output_digest = hashlib.sha256(output.encode()).hexdigest()
    command_digest = hashlib.sha256(
        json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode(),
    ).hexdigest()
    artifact_digest = _sha256(artifact_path)
    with state_lock(run):
        state = _load_state(run)
        revision = int(state.get("target_revision") or 1)
        if state.get("challenge_id") != challenge_id or state.get("input_fingerprint") != input_fingerprint:
            raise FastFlagError("challenge identity or input fingerprint changed during flag recording")
        if target_revision is not None and revision != target_revision:
            raise FastFlagError("remote receipt target revision mismatch")
        if state.get("sealed"):
            raise FastFlagError("sealed run is immutable")
        run_id = str(state.get("run_id") or run.name)
        receipt_material = {
            "run_id": run_id, "challenge_id": challenge_id,
            "input_fingerprint": input_fingerprint, "target_revision": revision,
            "branch_id": branch_id, "candidate": candidate,
            "observed_target": {
                "declared": matches[0].declared, "host": observed_host,
                "port": observed_port, "protocol": observed_protocol,
            },
            "command_argv": argv, "command_digest": command_digest,
            "output_digest": output_digest, "exploit_artifact": artifact,
            "exploit_artifact_digest": artifact_digest,
            "confidence": confidence,
            "validation_method": "REMOTE_SERVICE_ACCEPTANCE",
            **dict(receipt_metadata or {}),
        }
        receipt_id = hashlib.sha256(
            json.dumps(receipt_material, sort_keys=True, separators=(",", ":")).encode(),
        ).hexdigest()[:24]
        candidate_record = build_candidate(
            run_id=run_id, session_id=branch_id, candidate=candidate,
            source_type=str((receipt_metadata or {}).get("source_type") or "REMOTE_OUTPUT"),
            receipt_id=receipt_id, confidence=confidence,
            validation_method="REMOTE_SERVICE_ACCEPTANCE",
            status="SUBMISSION_RECOMMENDED" if confidence == "HIGH" else "OBSERVED_REMOTE",
        )
        receipt = {
            "schema_version": REMOTE_RECEIPT_SCHEMA_VERSION, "receipt_id": receipt_id,
            **receipt_material, "candidate_id": candidate_record["candidate_id"],
            "network_observed": True, "output_excerpt": _bounded_excerpt(output, candidate),
            "required_projections": list(REMOTE_PROJECTIONS),
            "created_at": utc_now(),
        }
        receipt_path = run / "flag-receipts" / f"remote-{receipt_id}.json"
        receipt_state_field = "remote_flag_receipt" if confidence == "HIGH" else "remote_candidate_receipt"
        if receipt_path.exists():
            existing = _load_json(receipt_path, "remote flag receipt")
            if _without_time(existing) != _without_time(receipt):
                raise FastFlagError("receipt_id already exists with conflicting content")
            if state.get(receipt_state_field) == str(receipt_path.relative_to(run)):
                return _response(
                    run, state_name, challenge_id, candidate, confidence, receipt_path,
                    matches[0], branch_id, candidate_record["candidate_id"], idempotent=True,
                )
        if state.get("remote_flag_receipt"):
            raise FastFlagError("verified remote flag run is immutable pending human submission feedback")
        candidate_payload = load_candidates(run)
        prior_candidate = next((
            row for row in candidate_payload.get("candidates", [])
            if row.get("candidate_id") == candidate_record["candidate_id"]
        ), None)
        if isinstance(prior_candidate, Mapping) and prior_candidate.get("status") == "REFUTED":
            raise FastFlagError("this exact candidate provenance was refuted by human submission")
        saved_candidate, _changed = upsert_candidate_payload(candidate_payload, candidate_record)
        history = list(state.get("flag_history") or [])
        if not any(row.get("receipt_id") == receipt_id for row in history if isinstance(row, Mapping)):
            history.append({
                "receipt_id": receipt_id, "candidate_id": saved_candidate["candidate_id"],
                "candidate": candidate, "state": "REMOTE_FLAG_OBTAINED" if pattern_match else "FLAG_CANDIDATE",
                "confidence": confidence, "created_at": receipt["created_at"],
                "target_revision": revision,
            })
        projected_state = dict(state)
        projected_state.update({
            "status": state_name, "competition_state": state_name,
            "flag_candidate": candidate, "active_candidate_id": saved_candidate["candidate_id"],
            "remote_flag": candidate if pattern_match else state.get("remote_flag"),
            "submission_recommended": state_name == "SUBMISSION_RECOMMENDED",
            receipt_state_field: str(receipt_path.relative_to(run)),
            "flag_history": history, "updated_at": receipt["created_at"],
        })
        projected_state["candidates"] = [
            {
                "candidate_id": row.get("candidate_id"), "status": row.get("status"),
                "confidence": row.get("confidence"), "session_id": row.get("session_id"),
            }
            for row in candidate_payload["candidates"]
        ]
        # Commit order keeps the terminal STATE projection last. A failure may
        # leave an orphan receipt, but never a receipt-less terminal state.
        atomic_json(receipt_path, receipt)
        _verification_failpoint("remote_receipt", "after", receipt)
        atomic_json(run / "candidates.json", candidate_payload)
        atomic_text(run / "RESULT.md", _fast_result(
            challenge_id, state_name, candidate, confidence, receipt_path, run, matches[0],
            saved_candidate["candidate_id"],
        ))
        atomic_json(run / "STATE.json", projected_state)
        workspace = challenge_workspace(run)
        if workspace != run and (workspace / "STATE.json").is_file():
            compatibility = dict(projected_state)
            compatibility["compatibility_view"] = True
            compatibility["authoritative_state"] = str((run / "STATE.json").relative_to(workspace))
            atomic_json(workspace / "STATE.json", compatibility)
        state = projected_state
    repaired = repair_remote_receipt_projections(run, receipt_ids={receipt_id}, suppress_errors=True)
    post_commit_warnings = repaired["errors"]
    response = _response(
        run, state_name, challenge_id, candidate, confidence, receipt_path,
        matches[0], branch_id, candidate_record["candidate_id"], idempotent=False,
    )
    response["race_transition"] = repaired.get("race_transition")
    response["post_commit_warnings"] = post_commit_warnings
    return response


def repair_remote_receipt_projections(
    root: Path, *, receipt_ids: set[str] | None = None,
    suppress_errors: bool = False,
) -> dict[str, Any]:
    run = resolve_active_run(root)
    repaired: list[str] = []
    errors: list[str] = []
    last_transition = None
    receipt_root = run / "flag-receipts"
    for path in sorted(receipt_root.glob("remote-*.json")) if receipt_root.is_dir() else []:
        receipt = _load_json(path, "remote flag receipt")
        receipt_id = str(receipt.get("receipt_id") or "")
        if not receipt_id and receipt.get("schema_version") is None and receipt.get("flag"):
            # Pre-v2 compatibility files carried only a displayed flag and
            # have no canonical evidence identity to replay. Preserve them,
            # but never promote them as authoritative receipts.
            continue
        if receipt_ids is not None and receipt_id not in receipt_ids:
            continue
        required = list(receipt.get("required_projections") or REMOTE_PROJECTIONS)
        ensure_projection_manifest(run, receipt, required)
        stages = (
            ("candidate_state", lambda r=receipt: recover_run_state(run, force=True)),
            ("result", lambda r=receipt, p=path: _repair_remote_result(run, p, r)),
            ("evidence", lambda r=receipt: _repair_remote_evidence(run, r)),
            ("timing", lambda r=receipt: update_run_manifest_timing(
                run, "flag_observed_at", str(r.get("created_at")),
            )),
            ("verified_event", lambda r=receipt: _repair_verified_event(run, r)),
            ("scheduler", lambda r=receipt: _optional_scheduler_update(
                run, str(r.get("branch_id") or ""),
                str(r.get("confidence") or "LOW"), receipt_id, strict=True,
            )),
            ("compatibility", lambda: _repair_remote_compatibility(run)),
        )
        for name, callback in stages:
            try:
                value, skipped = apply_projection(run, receipt, required, name, callback)
                if name == "verified_event" and isinstance(value, Mapping):
                    last_transition = value.get("race_transition")
                if not skipped and receipt_id not in repaired:
                    repaired.append(receipt_id)
            except Exception as exc:
                message = f"{receipt_id}:{name}: {exc}"
                errors.append(message[:2000])
                append_jsonl_fsync(run / "post-commit-errors.jsonl", {
                    "event": "FLAG_RECEIPT_PROJECTION_FAILED", "receipt_id": receipt_id,
                    "projection": name, "error": str(exc)[:2000], "created_at": utc_now(),
                }, label="post-commit error ledger")
                if not suppress_errors:
                    raise FastFlagError(message) from exc
    return {
        "run_id": run.name, "repaired_receipts": repaired,
        "errors": errors, "race_transition": last_transition,
    }


def _repair_remote_result(run: Path, receipt_path: Path, receipt: Mapping[str, Any]) -> None:
    state = _load_state(run)
    if state.get("competition_state") == "ACCEPTED":
        return
    observed = receipt.get("observed_target") if isinstance(receipt.get("observed_target"), Mapping) else {}
    target = Target(
        declared=str(observed.get("declared") or ""), host=str(observed.get("host") or ""),
        port=int(observed.get("port") or 0), scheme=str(observed.get("protocol") or "tcp"),
        organizer_declared=True,
    )
    confidence = str(receipt.get("confidence") or "LOW").upper()
    state_name = "SUBMISSION_RECOMMENDED" if confidence == "HIGH" else "FLAG_CANDIDATE"
    content = _fast_result(
        str(receipt.get("challenge_id") or ""), state_name,
        str(receipt.get("candidate") or ""), confidence, receipt_path, run,
        target, str(receipt.get("candidate_id") or ""),
    )
    destination = run / "RESULT.md"
    if destination.exists() and destination.read_text(encoding="utf-8") == content:
        return
    if destination.exists():
        existing = destination.read_text(encoding="utf-8")
        if existing.strip() and not existing.startswith("# Remote flag"):
            raise FastFlagError("RESULT.md conflicts with remote receipt projection")
    atomic_text(destination, content)


def _repair_remote_evidence(run: Path, receipt: Mapping[str, Any]) -> None:
    receipt_id = str(receipt.get("receipt_id") or "")
    path = run / "evidence.log"
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise FastFlagError("evidence log is malformed during projection repair") from exc
            if isinstance(row, Mapping) and row.get("event") == "remote_flag_receipt" and row.get("receipt_id") == receipt_id:
                return
    append_evidence(path, "remote_flag_receipt", {
        "receipt_id": receipt_id, "candidate_id": receipt.get("candidate_id"),
        "branch_id": receipt.get("branch_id"), "candidate": receipt.get("candidate"),
        "target": receipt.get("observed_target"), "network_observed": True,
        "run_id": receipt.get("run_id"),
        "input_fingerprint": receipt.get("input_fingerprint"),
        "target_revision": receipt.get("target_revision"),
        "confidence": receipt.get("confidence"),
    })


def _repair_verified_event(run: Path, receipt: Mapping[str, Any]) -> dict[str, Any]:
    from .events import publish_verified_event
    confidence = str(receipt.get("confidence") or "LOW").upper()
    return publish_verified_event(
        run, receipt=receipt,
        event_type="REMOTE_FLAG_OBTAINED" if confidence == "HIGH" else "FLAG_CANDIDATE",
        summary="declared remote flag receipt",
    )


def _repair_remote_compatibility(run: Path) -> None:
    workspace = challenge_workspace(run)
    path = workspace / "STATE.json"
    if workspace == run or not path.is_file() or path.is_symlink():
        return
    state = _load_state(run)
    projected = dict(state)
    projected["compatibility_view"] = True
    projected["authoritative_state"] = str((run / "STATE.json").relative_to(workspace))
    try:
        existing = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        existing = None
    if existing != projected:
        atomic_json(path, projected)


def mark_fully_verified(root: Path, *, input_fingerprint: str) -> dict[str, Any]:
    run = resolve_active_run(root, input_fingerprint=input_fingerprint)
    with state_lock(run):
        state = _load_state(run)
        if state.get("sealed"):
            raise FastFlagError("sealed run is immutable")
        if state.get("input_fingerprint") != input_fingerprint:
            raise FastFlagError("challenge input fingerprint changed")
        if not state.get("flag_candidate"):
            raise FastFlagError("cannot mark FULLY_VERIFIED without a flag candidate")
        if state.get("competition_state") == "SUBMISSION_RECOMMENDED" and not state.get("remote_flag_receipt"):
            raise FastFlagError("cannot verify a remote flag without its receipt")
        state["competition_state"] = "FULLY_VERIFIED"
        state["status"] = "FULLY_VERIFIED"
        state["submission_recommended"] = True
        state["updated_at"] = utc_now()
        atomic_json(run / "STATE.json", state)
    return {"state": "FULLY_VERIFIED", "flag": state["flag_candidate"]}


def _optional_scheduler_update(
    run: Path, branch_id: str, confidence: str, receipt_id: str, *, strict: bool = False,
) -> None:
    try:
        from .resources.scheduler import ResourceLedger, detect_capacity
        ledger = ResourceLedger(run)
        if ledger.state_path.exists():
            ledger.flag_event({
                "type": "REMOTE_FLAG_OBTAINED" if confidence == "HIGH" else "FLAG_CANDIDATE",
                "session_id": branch_id, "event_id": f"flag-receipt-{receipt_id}",
            })
            ledger.rebalance(
                detect_capacity(workspace=run),
                remote_flag_session=branch_id if confidence == "HIGH" else None,
            )
    except Exception as exc:
        append_jsonl_fsync(run / "scheduler-errors.jsonl", {
            "event": "FLAG_RECEIPT_SCHEDULER_UPDATE_FAILED", "receipt_id": receipt_id,
            "error": str(exc), "created_at": utc_now(),
        }, label="scheduler error ledger")
        if strict:
            raise


def _response(
    run: Path, state: str, challenge_id: str, candidate: str, confidence: str,
    receipt_path: Path, target: Target, branch_id: str, candidate_id: str, *, idempotent: bool,
) -> dict[str, Any]:
    from .progress import load_solve_policy
    maximum_verifiers = int(
        load_solve_policy()["remote_transition"]["maximum_optional_verifiers"]
    )
    return {
        "state": state, "remote_state": "REMOTE_FLAG_OBTAINED" if confidence == "HIGH" else "FLAG_CANDIDATE",
        "challenge_id": challenge_id, "run_id": run.name, "candidate_id": candidate_id,
        "flag": candidate, "confidence": confidence, "source": "declared remote",
        "receipt": str(receipt_path),
        "recommendation": "submit immediately" if confidence == "HIGH" else "verify candidate provenance",
        "full_clean_replay_required_before_human_submission": False,
        "branch_actions": {
            "prioritize": branch_id, "stop_low_value_branches": confidence == "HIGH",
            "maximum_verifiers_to_keep": maximum_verifiers if confidence == "HIGH" else None,
        },
        "automatic_submission_attempted": False, "idempotent": idempotent,
    }


def _fast_result(
    challenge_id: str, state: str, candidate: str, confidence: str,
    receipt_path: Path, run: Path, target: Target, candidate_id: str,
) -> str:
    return (
        f"# Remote flag — {challenge_id}\n\n"
        f"- State: **{state}**\n- Candidate ID: `{candidate_id}`\n"
        f"- Flag: `{candidate}`\n- Confidence: **{confidence}**\n"
        f"- Source: declared remote `{target.host}:{target.port}`\n"
        f"- Receipt: `{receipt_path.relative_to(run)}`\n"
        "- Recommendation: submit immediately\n"
        "- Full clean replay: not required before human submission\n\n"
        "Submission remains manual; CTF-OS did not contact a submission endpoint.\n"
    )


def _load_state(run: Path) -> dict[str, Any]:
    return _load_json(run / "STATE.json", "run state")


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise FastFlagError(f"{label} is missing or unsafe")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FastFlagError(f"{label} is malformed") from exc
    if not isinstance(payload, dict):
        raise FastFlagError(f"{label} is not an object")
    return payload


def _argv(values: Sequence[str]) -> list[str]:
    if isinstance(values, (str, bytes)) or not values or len(values) > 256:
        raise FastFlagError("remote command receipt requires a direct argv array")
    result = []
    forbidden = {";", "&&", "||", "|", ">", ">>", "<", "&"}
    for value in values:
        text = str(value)
        if not text or text in forbidden or any(char in text for char in "\0\r\n"):
            raise FastFlagError("remote command receipt must not contain shell operators")
        result.append(text)
    return result


def _relative_artifact(value: str) -> str:
    path = Path(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise FastFlagError("exploit artifact must be a safe relative path")
    return path.as_posix()


def _looks_placeholder(candidate: str) -> bool:
    normalized = candidate.casefold()
    return any(word in normalized for word in ("...", "example", "placeholder", "dummy", "sample", "your_flag", "yourflag"))


def _bounded_excerpt(output: str, candidate: str) -> str:
    index = output.find(candidate)
    start = max(0, index - 256)
    end = min(len(output), index + len(candidate) + 256)
    return output[start:end].replace("\x00", "\\0")


def _without_time(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "created_at"}


def _verification_failpoint(
    boundary: str, phase: str, receipt: Mapping[str, Any],
) -> None:
    """Private no-op seam used only by fault-injection tests."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_copy_artifact(source: Path, destination: Path) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with source.open("rb") as input_handle, os.fdopen(descriptor, "wb") as output_handle:
            shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)
            output_handle.flush()
            os.fsync(output_handle.fileno())
        os.replace(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
