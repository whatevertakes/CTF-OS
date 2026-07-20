"""Run-bound flag candidate identity and exactness rules."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
from typing import Any

from .workspace import atomic_json, resolve_active_run, state_lock, utc_now


CANDIDATE_SCHEMA_VERSION = 1
CANDIDATE_STATUSES = frozenset({
    "PROPOSED", "VALIDATED_LOCAL", "OBSERVED_REMOTE", "SUBMISSION_RECOMMENDED",
    "REFUTED", "ACCEPTED",
})
CONFIDENCE_LEVELS = frozenset({"LOW", "MEDIUM", "HIGH"})
STATIC_SOURCE_TYPES = frozenset({"STATIC", "STATIC_ANALYSIS", "DETERMINISTIC_EXTRACTION"})
EXACT_VALIDATION_METHODS = frozenset({
    "ORIGINAL_VALIDATOR", "TWO_PATH_EXACT_MATCH", "REMOTE_SERVICE_ACCEPTANCE",
    "EXACT_BYTE_PROOF",
})


class CandidateError(ValueError):
    pass


def build_candidate(
    *, run_id: str, session_id: str, candidate: str, source_type: str,
    receipt_id: str | None, confidence: str, validation_method: str,
    status: str = "PROPOSED", created_at: str | None = None,
) -> dict[str, Any]:
    text = _text(candidate, "candidate", 4096)
    source = _token(source_type, "source_type")
    method = _token(validation_method, "validation_method")
    normalized_confidence = confidence.strip().upper()
    normalized_status = status.strip().upper()
    if normalized_confidence not in CONFIDENCE_LEVELS:
        raise CandidateError(f"confidence must be one of {sorted(CONFIDENCE_LEVELS)}")
    if normalized_status not in CANDIDATE_STATUSES:
        raise CandidateError(f"candidate status must be one of {sorted(CANDIDATE_STATUSES)}")
    if source in STATIC_SOURCE_TYPES and method not in EXACT_VALIDATION_METHODS:
        if normalized_confidence == "HIGH":
            normalized_confidence = "MEDIUM"
        if normalized_status in {"SUBMISSION_RECOMMENDED", "ACCEPTED"}:
            raise CandidateError("static candidate lacks exact-byte validation proof")
    if normalized_status == "SUBMISSION_RECOMMENDED" and method != "REMOTE_SERVICE_ACCEPTANCE":
        raise CandidateError("submission recommendation requires a verified remote receipt")
    if method in EXACT_VALIDATION_METHODS and not receipt_id:
        raise CandidateError("exact validation method requires an evidence receipt")
    material = {
        "run_id": _token(run_id, "run_id"), "session_id": _token(session_id, "session_id"),
        "candidate": text, "source_type": source, "receipt_id": receipt_id,
        "validation_method": method,
    }
    candidate_id = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode(),
    ).hexdigest()[:24]
    return {
        "schema_version": CANDIDATE_SCHEMA_VERSION, "candidate_id": candidate_id,
        **material, "confidence": normalized_confidence, "validation_method": method,
        "status": normalized_status, "created_at": created_at or utc_now(),
    }


def record_candidate(
    root: Path, *, session_id: str, candidate: str, source_type: str,
    receipt_id: str | None = None, confidence: str = "LOW",
    validation_method: str = "UNVALIDATED", status: str = "PROPOSED",
) -> dict[str, Any]:
    run = resolve_active_run(root)
    protected = status.strip().upper()
    if protected in {"SUBMISSION_RECOMMENDED", "ACCEPTED"}:
        raise CandidateError(
            "candidate submission states may be created only by flag-receipt-save or human feedback"
        )
    with state_lock(run):
        state = _state(run)
        if state.get("sealed"):
            raise CandidateError("sealed run is immutable")
        if state.get("remote_flag_receipt"):
            raise CandidateError("verified remote flag run is immutable pending human submission feedback")
        record = build_candidate(
            run_id=str(state.get("run_id") or run.name), session_id=session_id,
            candidate=candidate, source_type=source_type, receipt_id=receipt_id,
            confidence=confidence, validation_method=validation_method, status=status,
        )
        payload = load_candidates(run)
        saved, changed = upsert_candidate_payload(payload, record)
        if changed:
            atomic_json(run / "candidates.json", payload)
        _project_candidates(state, payload)
        state["updated_at"] = utc_now()
        atomic_json(run / "STATE.json", state)
    return {**saved, "idempotent": not changed}


def load_candidates(root: Path) -> dict[str, Any]:
    run = resolve_active_run(root)
    path = run / "candidates.json"
    if not path.exists():
        return {"schema_version": CANDIDATE_SCHEMA_VERSION, "candidates": []}
    if path.is_symlink() or not path.is_file():
        raise CandidateError("candidate store is missing or unsafe")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CandidateError("candidate store is malformed") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != CANDIDATE_SCHEMA_VERSION:
        raise CandidateError("candidate store schema is unsupported")
    rows = payload.get("candidates")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise CandidateError("candidate store rows are malformed")
    return payload


def candidate_by_id(root: Path, candidate_id: str) -> dict[str, Any]:
    matches = [row for row in load_candidates(root)["candidates"] if row.get("candidate_id") == candidate_id]
    if len(matches) != 1:
        raise CandidateError("candidate_id does not exist in this run")
    return dict(matches[0])


def upsert_candidate_payload(
    payload: dict[str, Any], record: Mapping[str, Any],
) -> tuple[dict[str, Any], bool]:
    rows = payload.setdefault("candidates", [])
    existing = next((row for row in rows if row.get("candidate_id") == record.get("candidate_id")), None)
    if existing is not None:
        immutable = {key: value for key, value in existing.items() if key not in {"status", "confidence", "updated_at"}}
        proposed = {key: value for key, value in record.items() if key not in {"status", "confidence", "updated_at"}}
        if immutable != proposed:
            raise CandidateError("candidate_id conflicts with existing provenance")
        rank = {"PROPOSED": 0, "VALIDATED_LOCAL": 1, "OBSERVED_REMOTE": 2, "SUBMISSION_RECOMMENDED": 3, "REFUTED": 4, "ACCEPTED": 5}
        changed = rank[str(record["status"])] > rank[str(existing["status"])] or (
            record.get("confidence") != existing.get("confidence") and existing.get("status") not in {"REFUTED", "ACCEPTED"}
        )
        if changed:
            existing["status"] = record["status"]
            existing["confidence"] = record["confidence"]
            existing["updated_at"] = utc_now()
        return existing, changed
    saved = dict(record)
    rows.append(saved)
    rows.sort(key=lambda row: (str(row.get("created_at", "")), str(row.get("candidate_id", ""))))
    return saved, True


def _project_candidates(state: dict[str, Any], payload: Mapping[str, Any]) -> None:
    rows = payload.get("candidates", []) if isinstance(payload.get("candidates"), list) else []
    state["candidates"] = [
        {
            "candidate_id": row.get("candidate_id"), "status": row.get("status"),
            "confidence": row.get("confidence"), "session_id": row.get("session_id"),
        }
        for row in rows if isinstance(row, Mapping)
    ]


def _state(run: Path) -> dict[str, Any]:
    path = run / "STATE.json"
    if path.is_symlink() or not path.is_file():
        raise CandidateError("run state is missing or unsafe")
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CandidateError("run state is malformed") from exc
    if not isinstance(state, dict):
        raise CandidateError("run state is not an object")
    return state


def _text(value: Any, field: str, maximum: int) -> str:
    text = str(value).strip()
    if not text or len(text) > maximum or any(char in text for char in "\0\r\n"):
        raise CandidateError(f"{field} is invalid")
    return text


def _token(value: Any, field: str) -> str:
    text = _text(value, field, 128)
    if any(char.isspace() for char in text):
        text = text.upper().replace("-", "_")
    return text.upper() if field in {"source_type", "validation_method"} else text
