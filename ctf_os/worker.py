"""Structured, branch-private worker results for Sol-owned synthesis."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any

from .workspace import atomic_json, state_lock


WORKER_RESULT_SCHEMA_VERSION = 1
WORKER_STATUSES = frozenset({
    "SUPPORTED", "REFUTED", "PARTIAL", "INCONCLUSIVE", "ERROR", "FLAG_CANDIDATE",
})
CONFIDENCE_LEVELS = frozenset({"LOW", "MEDIUM", "HIGH"})
CHECKPOINT_TYPES = frozenset({
    "SUPPORTED_FACT", "REJECTED_HYPOTHESIS", "EXPLOIT_PRIMITIVE", "BLOCKER",
    "ARTIFACT_READY", "NEXT_EXPERIMENT", "FLAG_CANDIDATE", "REMOTE_FLAG_OBTAINED",
    "SERVICE_CRASHED", "ENVIRONMENT_DISCOVERY", "NEED_HELP", "OPERATOR_HINT",
})
CHECKPOINT_SCHEMA_VERSION = 1


class WorkerResultError(ValueError):
    """Raised when a worker result is malformed or references unsafe evidence."""


def save_worker_result(worker_root: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and atomically save one worker's result under its private root.

    Reported mutations are preserved for Sol's review. Branch-private service
    and explicitly challenge-scoped cloud mutations are valid; shared service
    mutations remain policy violations.
    """

    normalized = validate_worker_result(worker_root, payload)
    mutations = normalized["service_mutations"]
    forbidden_mutations = [item for item in mutations if not _allowed_worker_mutation(item, worker_root.name)]
    if forbidden_mutations:
        violations = normalized["policy_violations"]
        if not any(
            isinstance(item, Mapping) and item.get("code") == "SERVICE_MUTATION_REPORTED"
            for item in violations
        ):
            violations.append({
                "code": "SERVICE_MUTATION_REPORTED",
                "message": "A child worker reported a shared service lifecycle mutation.",
                "mutations": forbidden_mutations,
            })
    atomic_json(_safe_result_path(worker_root), normalized)
    return normalized


def _allowed_worker_mutation(value: Any, session_id: str) -> bool:
    if not isinstance(value, Mapping):
        return False
    scope = str(value.get("scope") or value.get("service_scope") or "")
    if scope == "branch-private":
        return value.get("branch_id") == session_id and value.get("target") != "challenge-service"
    if scope == "challenge-cloud":
        return bool(value.get("account_scope") and value.get("ledger_event_id"))
    return False


def load_worker_result(path: Path) -> dict[str, Any]:
    """Load a saved result and revalidate its schema and file references."""

    if path.name != "result.json" or not path.is_file() or path.is_symlink():
        raise WorkerResultError(f"worker result is missing or unsafe: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkerResultError(f"worker result is not valid JSON: {path}") from exc
    if not isinstance(payload, Mapping):
        raise WorkerResultError("worker result must be a JSON object")
    return validate_worker_result(path.parent, payload)


def validate_worker_result(worker_root: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return a JSON-safe normalized worker result or raise ``WorkerResultError``."""

    root = _safe_worker_root(worker_root)
    required = {
        "schema_version", "session_id", "parent_session_id", "challenge_id", "role",
        "input_fingerprint",
        "status", "summary", "hypotheses", "artifacts", "flag_candidates",
        "recommended_next_step", "service_mutations", "policy_violations",
        "started_at", "finished_at",
    }
    missing = sorted(required.difference(payload))
    if missing:
        raise WorkerResultError(f"worker result is missing required fields: {', '.join(missing)}")
    if payload.get("schema_version") != WORKER_RESULT_SCHEMA_VERSION:
        raise WorkerResultError(f"worker result schema_version must be {WORKER_RESULT_SCHEMA_VERSION}")

    result: dict[str, Any] = {
        "schema_version": WORKER_RESULT_SCHEMA_VERSION,
        "session_id": _identifier(payload["session_id"], "session_id"),
        "parent_session_id": _identifier(payload["parent_session_id"], "parent_session_id"),
        "challenge_id": _text(payload["challenge_id"], "challenge_id"),
        "input_fingerprint": _identifier(payload["input_fingerprint"], "input_fingerprint"),
        "role": _identifier(payload["role"], "role"),
        "status": _status(payload["status"], "status"),
        "summary": _text(payload["summary"], "summary"),
        "hypotheses": _hypotheses(root, payload["hypotheses"]),
        "artifacts": _paths(root, payload["artifacts"], "artifacts"),
        "flag_candidates": _flag_candidates(payload["flag_candidates"]),
        "recommended_next_step": _optional_text(payload["recommended_next_step"], "recommended_next_step"),
        "service_mutations": _json_list(payload["service_mutations"], "service_mutations"),
        "policy_violations": _json_list(payload["policy_violations"], "policy_violations"),
        "started_at": _timestamp(payload["started_at"], "started_at"),
        "finished_at": _timestamp(payload["finished_at"], "finished_at"),
    }
    # Backward-compatible clean-room metadata.  Old schema-v1 results remain
    # valid, while verifiers can state their role without changing replay.
    result["verifier_role"] = _nullable_text(payload.get("verifier_role"), "verifier_role")
    independent = payload.get("independent_verification", False)
    if not isinstance(independent, bool):
        raise WorkerResultError("independent_verification must be a boolean")
    result["independent_verification"] = independent
    if result["session_id"] != root.name:
        raise WorkerResultError("session_id must match the worker directory name")
    if _parse_timestamp(result["finished_at"]) < _parse_timestamp(result["started_at"]):
        raise WorkerResultError("finished_at must not be earlier than started_at")
    return result


def save_worker_checkpoint(
    worker_root: Path, *, parent_session_id: str, challenge_id: str,
    input_fingerprint: str, checkpoint_type: str, summary: str,
    evidence: list[str], artifacts: list[str], useful_for: list[str],
    recommended_action: str, confidence: float,
) -> dict[str, Any]:
    """Atomically save a compact checkpoint in the matching private worker root."""

    root = _safe_worker_root(worker_root)
    if checkpoint_type not in CHECKPOINT_TYPES:
        raise WorkerResultError(f"checkpoint type must be one of {sorted(CHECKPOINT_TYPES)}")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0.0 <= float(confidence) <= 1.0:
        raise WorkerResultError("checkpoint confidence must be between 0 and 1")
    compact_summary = _limited_text(summary, "summary", 1000)
    action = _limited_optional_text(recommended_action, "recommended_action", 1000)
    safe_evidence = _paths_limited(root, evidence, "evidence", maximum=16)
    safe_artifacts = _paths_limited(root, artifacts, "artifacts", maximum=16)
    targets = _short_strings(useful_for, "useful_for", maximum=16, item_limit=128)
    solve_root = root.parents[1]
    state_path = solve_root / "STATE.json"
    if state_path.is_file() and not state_path.is_symlink():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise WorkerResultError("challenge STATE.json is invalid") from exc
        if state.get("input_fingerprint") != input_fingerprint:
            raise WorkerResultError("checkpoint input fingerprint does not match current challenge state")
    checkpoints = root / "checkpoints"
    if checkpoints.is_symlink():
        raise WorkerResultError("checkpoint directory must not be a symlink")
    with state_lock(solve_root):
        checkpoints.mkdir(parents=True, exist_ok=True)
        existing = sorted(checkpoints.glob("*.json"))
        sequence = 1
        for path in existing:
            loaded = load_worker_checkpoint(path)
            sequence = max(sequence, int(loaded["sequence"]) + 1)
        payload = {
            "schema_version": CHECKPOINT_SCHEMA_VERSION, "session_id": root.name,
            "parent_session_id": _identifier(parent_session_id, "parent_session_id"),
            "challenge_id": _text(challenge_id, "challenge_id"),
            "input_fingerprint": _identifier(input_fingerprint, "input_fingerprint"),
            "sequence": sequence, "type": checkpoint_type, "summary": compact_summary,
            "evidence": safe_evidence, "artifacts": safe_artifacts, "useful_for": targets,
            "recommended_action": action, "confidence": float(confidence),
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        target = checkpoints / f"{sequence:06d}.json"
        if target.is_symlink() or target.exists():
            raise WorkerResultError("checkpoint sequence path already exists or is unsafe")
        atomic_json(target, payload)
    return payload


def load_worker_checkpoint(path: Path) -> dict[str, Any]:
    if path.is_symlink() or path.parent.is_symlink() or not path.is_file() or path.parent.name != "checkpoints":
        raise WorkerResultError(f"worker checkpoint is missing or unsafe: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkerResultError(f"worker checkpoint is not valid JSON: {path}") from exc
    if not isinstance(payload, Mapping):
        raise WorkerResultError("worker checkpoint must be a JSON object")
    root = _safe_worker_root(path.parent.parent)
    required = {"schema_version", "session_id", "parent_session_id", "challenge_id", "input_fingerprint", "sequence", "type", "summary", "evidence", "artifacts", "useful_for", "recommended_action", "confidence", "created_at"}
    missing = required.difference(payload)
    if missing or payload.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
        raise WorkerResultError("worker checkpoint schema is incomplete or unsupported")
    if payload.get("session_id") != root.name:
        raise WorkerResultError("checkpoint session_id must match the worker directory")
    if payload.get("type") not in CHECKPOINT_TYPES:
        raise WorkerResultError("checkpoint contains an unsupported type")
    if not isinstance(payload.get("sequence"), int) or payload["sequence"] < 1:
        raise WorkerResultError("checkpoint sequence must be a positive integer")
    expected_name = f"{payload['sequence']:06d}.json"
    if path.name != expected_name:
        raise WorkerResultError("checkpoint filename does not match sequence")
    _limited_text(payload["summary"], "summary", 1000)
    _paths_limited(root, payload["evidence"], "evidence", maximum=16)
    _paths_limited(root, payload["artifacts"], "artifacts", maximum=16)
    _short_strings(payload["useful_for"], "useful_for", maximum=16, item_limit=128)
    _timestamp(payload["created_at"], "created_at")
    if not isinstance(payload["confidence"], (int, float)) or isinstance(payload["confidence"], bool) or not 0 <= payload["confidence"] <= 1:
        raise WorkerResultError("checkpoint confidence must be between 0 and 1")
    return dict(payload)


def collect_worker_checkpoints(
    workers_root: Path, *, input_fingerprint: str, since_sequence: int = 0,
) -> list[dict[str, Any]]:
    if since_sequence < 0:
        raise WorkerResultError("since_sequence must be non-negative")
    rows: list[dict[str, Any]] = []
    if not workers_root.exists():
        return rows
    if workers_root.is_symlink() or not workers_root.is_dir():
        raise WorkerResultError("workers root is unsafe")
    for path in sorted(workers_root.glob("*/checkpoints/*.json")):
        item = load_worker_checkpoint(path)
        if item["input_fingerprint"] == input_fingerprint and item["sequence"] > since_sequence:
            rows.append(item)
    rows.sort(key=lambda item: (item["created_at"], item["session_id"], item["sequence"]))
    return rows


def merge_worker_checkpoints(workers_root: Path, *, input_fingerprint: str) -> dict[str, Any]:
    """Preserve every observation and make repeated merges byte-equivalent."""

    rows = collect_worker_checkpoints(workers_root, input_fingerprint=input_fingerprint)
    merged = {"schema_version": 1, "input_fingerprint": input_fingerprint, "checkpoints": rows}
    atomic_json(workers_root / "MERGED_CHECKPOINTS.json", merged)
    return merged


def merge_worker_results(results: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Build Sol's compact integration view from already validated worker results.

    Equal claims are grouped.  Every worker observation remains in the group, so
    supported/refuted conflicts are explicit rather than resolved by this helper.
    """

    rows = [dict(item) for item in results]
    for item in rows:
        # Merge may be used immediately after ``save_worker_result`` or after a
        # caller has loaded validated JSON.  Keep it pure and reject weak shapes.
        _validate_merge_shape(item)
    ordered = sorted(rows, key=lambda item: (_priority(item), str(item["session_id"])))

    grouped: dict[str, dict[str, Any]] = {}
    for result in ordered:
        for hypothesis in result["hypotheses"]:
            key = _claim_key(hypothesis["claim"])
            group = grouped.setdefault(key, {
                "claim": hypothesis["claim"], "statuses": [], "conflict": False,
                "observations": [],
            })
            observation = dict(hypothesis)
            observation["session_id"] = result["session_id"]
            observation["role"] = result["role"]
            group["observations"].append(observation)
            if hypothesis["status"] not in group["statuses"]:
                group["statuses"].append(hypothesis["status"])

    hypotheses = list(grouped.values())
    for group in hypotheses:
        group["statuses"].sort(key=_status_priority)
        group["conflict"] = "SUPPORTED" in group["statuses"] and "REFUTED" in group["statuses"]
    hypotheses.sort(key=lambda item: (_status_priority(item["statuses"][0]), _claim_key(item["claim"])))

    return {
        "schema_version": 1,
        "results": ordered,
        "hypotheses": hypotheses,
        "flag_candidates": [
            {"session_id": item["session_id"], "candidate": candidate}
            for item in ordered for candidate in item["flag_candidates"]
        ],
        "policy_violations": [
            {"session_id": item["session_id"], "violation": violation}
            for item in ordered for violation in item["policy_violations"]
        ],
    }


def merge_worker_result_files(
    paths: Iterable[Path], *, input_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Load, revalidate, prioritize, and merge saved worker result files."""

    loaded = [load_worker_result(path) for path in paths]
    if input_fingerprint is not None:
        loaded = [item for item in loaded if item["input_fingerprint"] == input_fingerprint]
    return merge_worker_results(loaded)


def _hypotheses(root: Path, value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise WorkerResultError("hypotheses must be an array")
    hypotheses: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise WorkerResultError(f"hypotheses[{index}] must be an object")
        required = {"claim", "status", "confidence", "evidence", "commands", "kill_condition", "reopen_condition"}
        missing = sorted(required.difference(item))
        if missing:
            raise WorkerResultError(f"hypotheses[{index}] is missing: {', '.join(missing)}")
        confidence = item["confidence"]
        if not isinstance(confidence, str) or confidence not in CONFIDENCE_LEVELS:
            raise WorkerResultError(f"hypotheses[{index}].confidence must be LOW, MEDIUM, or HIGH")
        commands = item["commands"]
        if not isinstance(commands, list) or any(not isinstance(command, str) or not command for command in commands):
            raise WorkerResultError(f"hypotheses[{index}].commands must be an array of non-empty strings")
        hypotheses.append({
            "claim": _text(item["claim"], f"hypotheses[{index}].claim"),
            "status": _status(item["status"], f"hypotheses[{index}].status"),
            "confidence": confidence,
            "evidence": _paths(root, item["evidence"], f"hypotheses[{index}].evidence"),
            "commands": list(commands),
            "kill_condition": _nullable_text(item["kill_condition"], f"hypotheses[{index}].kill_condition"),
            "reopen_condition": _nullable_text(item["reopen_condition"], f"hypotheses[{index}].reopen_condition"),
        })
    return hypotheses


def _paths(root: Path, value: Any, field: str) -> list[str]:
    if not isinstance(value, list):
        raise WorkerResultError(f"{field} must be an array")
    paths: list[str] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, str) or not raw:
            raise WorkerResultError(f"{field}[{index}] must be a non-empty relative path")
        relative = Path(raw)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise WorkerResultError(f"{field}[{index}] is not a safe relative path: {raw!r}")
        candidate = root / relative
        current = root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise WorkerResultError(f"{field}[{index}] must not traverse a symlink: {raw!r}")
        try:
            candidate.resolve(strict=True).relative_to(root)
        except (FileNotFoundError, ValueError) as exc:
            raise WorkerResultError(f"{field}[{index}] is outside the worker root or missing: {raw!r}") from exc
        if not candidate.is_file():
            raise WorkerResultError(f"{field}[{index}] is not a regular file: {raw!r}")
        paths.append(relative.as_posix())
    return paths


def _paths_limited(root: Path, value: Any, field: str, *, maximum: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise WorkerResultError(f"{field} must be an array with at most {maximum} entries")
    return _paths(root, value, field)


def _limited_text(value: Any, field: str, maximum: int) -> str:
    text = _text(value, field)
    if len(text) > maximum:
        raise WorkerResultError(f"{field} must be at most {maximum} characters")
    return text


def _limited_optional_text(value: Any, field: str, maximum: int) -> str:
    text = _optional_text(value, field)
    if len(text) > maximum:
        raise WorkerResultError(f"{field} must be at most {maximum} characters")
    return text


def _short_strings(value: Any, field: str, *, maximum: int, item_limit: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise WorkerResultError(f"{field} must be an array with at most {maximum} entries")
    return [_limited_text(item, f"{field}[{index}]", item_limit) for index, item in enumerate(value)]


def _flag_candidates(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise WorkerResultError("flag_candidates must be an array")
    normalized: list[Any] = []
    for index, item in enumerate(value):
        if isinstance(item, str) and item:
            normalized.append(item)
        elif isinstance(item, Mapping) and isinstance(item.get("candidate"), str) and item["candidate"]:
            normalized.append(dict(item))
        else:
            raise WorkerResultError(f"flag_candidates[{index}] must be a string or candidate object")
    return normalized


def _safe_worker_root(worker_root: Path) -> Path:
    if worker_root.is_symlink() or not worker_root.is_dir():
        raise WorkerResultError(f"worker root is missing or unsafe: {worker_root}")
    return worker_root.resolve()


def _safe_result_path(worker_root: Path) -> Path:
    root = _safe_worker_root(worker_root)
    path = root / "result.json"
    if path.is_symlink():
        raise WorkerResultError("worker result path must not be a symlink")
    return path


def _identifier(value: Any, field: str) -> str:
    text = _text(value, field)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}", text):
        raise WorkerResultError(f"{field} contains unsupported characters")
    return text


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or any(character in value for character in "\0\r"):
        raise WorkerResultError(f"{field} must be a non-empty string")
    return value.strip()


def _optional_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or any(character in value for character in "\0\r"):
        raise WorkerResultError(f"{field} must be a string")
    return value.strip()


def _nullable_text(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _optional_text(value, field)


def _status(value: Any, field: str) -> str:
    if not isinstance(value, str) or value not in WORKER_STATUSES:
        raise WorkerResultError(f"{field} must be one of {sorted(WORKER_STATUSES)}")
    return value


def _timestamp(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise WorkerResultError(f"{field} must be an ISO-8601 timestamp")
    _parse_timestamp(value, field)
    return value


def _parse_timestamp(value: str, field: str = "timestamp") -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise WorkerResultError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise WorkerResultError(f"{field} must include a timezone")
    return parsed


def _json_list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise WorkerResultError(f"{field} must be an array")
    try:
        return json.loads(json.dumps(value, ensure_ascii=False))
    except (TypeError, ValueError) as exc:
        raise WorkerResultError(f"{field} must contain JSON values") from exc


def _validate_merge_shape(item: Mapping[str, Any]) -> None:
    required = {"session_id", "role", "status", "hypotheses", "flag_candidates", "policy_violations"}
    if required.difference(item):
        raise WorkerResultError("merge input is not a validated worker result")
    _status(item["status"], "status")
    if not all(isinstance(item[field], list) for field in ("hypotheses", "flag_candidates", "policy_violations")):
        raise WorkerResultError("merge input contains malformed arrays")
    for hypothesis in item["hypotheses"]:
        if not isinstance(hypothesis, Mapping) or not {"claim", "status", "confidence"}.issubset(hypothesis):
            raise WorkerResultError("merge input contains a malformed hypothesis")
        _text(hypothesis["claim"], "hypothesis claim")
        _status(hypothesis["status"], "hypothesis status")
        if hypothesis["confidence"] not in CONFIDENCE_LEVELS:
            raise WorkerResultError("merge input contains an invalid hypothesis confidence")


def _priority(item: Mapping[str, Any]) -> int:
    if item["status"] == "FLAG_CANDIDATE" or item["flag_candidates"]:
        return 0
    if any(h["status"] == "SUPPORTED" and h["confidence"] == "HIGH" for h in item["hypotheses"]):
        return 1
    if item["status"] == "REFUTED" or any(h["status"] == "REFUTED" for h in item["hypotheses"]):
        return 2
    if item["status"] in {"SUPPORTED", "PARTIAL"} or any(h["status"] in {"SUPPORTED", "PARTIAL"} for h in item["hypotheses"]):
        return 3
    return 4


def _status_priority(status: str) -> int:
    return {
        "FLAG_CANDIDATE": 0, "SUPPORTED": 1, "REFUTED": 2,
        "PARTIAL": 3, "INCONCLUSIVE": 4, "ERROR": 5,
    }[status]


def _claim_key(claim: str) -> str:
    return " ".join(claim.casefold().split())
