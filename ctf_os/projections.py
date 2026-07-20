"""Restartable receipt projection manifests.

Authoritative receipts describe which derived views are required.  This
module records only the application state of those views; deleting a
projection manifest never deletes or weakens the receipt it belongs to.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import json
from pathlib import Path
from typing import Any

from .workspace import append_jsonl_fsync, atomic_json, state_lock, utc_now


PROJECTION_SCHEMA_VERSION = 1
PROJECTION_STATES = frozenset({"PENDING", "APPLIED", "FAILED", "NOT_REQUIRED"})


class ProjectionError(RuntimeError):
    pass


def projection_path(run: Path, receipt_id: str) -> Path:
    return run / "receipt-projections" / f"{receipt_id}.json"


def ensure_projection_manifest(
    run: Path, receipt: Mapping[str, Any], required: Sequence[str],
) -> dict[str, Any]:
    """Create or validate a receipt's projection manifest.

    The required set is also embedded in the authoritative receipt, so a
    crash immediately after receipt persistence is recoverable even when this
    file has not been created yet.
    """

    receipt_id = _identifier(receipt.get("receipt_id"), "receipt_id")
    names = _projection_names(required)
    path = projection_path(run, receipt_id)
    with state_lock(run):
        if path.exists():
            payload = _load_manifest(path)
            if payload.get("receipt_id") != receipt_id:
                raise ProjectionError("projection manifest receipt identity mismatch")
            for field in ("run_id", "challenge_id", "input_fingerprint", "target_revision"):
                if payload.get(field) != receipt.get(field):
                    raise ProjectionError(
                        f"projection manifest {field} conflicts with authoritative receipt"
                    )
            existing = payload.get("projections")
            if not isinstance(existing, dict):
                raise ProjectionError("projection manifest projections are malformed")
            if set(existing) != set(names):
                raise ProjectionError("projection manifest required set conflicts with receipt")
            return payload
        payload = {
            "schema_version": PROJECTION_SCHEMA_VERSION,
            "receipt_id": receipt_id,
            "run_id": receipt.get("run_id"),
            "challenge_id": receipt.get("challenge_id"),
            "input_fingerprint": receipt.get("input_fingerprint"),
            "target_revision": receipt.get("target_revision"),
            "projections": {
                name: {
                    "status": "PENDING", "attempts": 0,
                    "last_error": None, "updated_at": receipt.get("created_at"),
                }
                for name in names
            },
        }
        atomic_json(path, payload)
        _projection_failpoint("manifest", "after", receipt)
        return payload


def mark_not_required(
    run: Path, receipt: Mapping[str, Any], required: Sequence[str], name: str,
) -> dict[str, Any]:
    return _update_status(run, receipt, required, name, "NOT_REQUIRED", error=None)


def apply_projection(
    run: Path, receipt: Mapping[str, Any], required: Sequence[str], name: str,
    apply: Callable[[], Any],
) -> tuple[Any, bool]:
    """Apply one missing projection and durably record its outcome.

    The callback must itself be idempotent.  If a test-injected failure occurs
    after the callback, retrying verifies/replays only this projection.
    """

    manifest = ensure_projection_manifest(run, receipt, required)
    row = manifest["projections"].get(name)
    if not isinstance(row, dict):
        raise ProjectionError(f"projection {name!r} is not required by this receipt")
    if row.get("status") in {"APPLIED", "NOT_REQUIRED"}:
        return None, True
    try:
        _projection_failpoint(name, "before", receipt)
        result = apply()
        _projection_failpoint(name, "after", receipt)
    except Exception as exc:
        _update_status(run, receipt, required, name, "FAILED", error=str(exc))
        append_jsonl_fsync(run / "projection-errors.jsonl", {
            "schema_version": 1, "receipt_id": receipt.get("receipt_id"),
            "projection": name, "error_type": type(exc).__name__,
            "error": str(exc)[:2000], "created_at": utc_now(),
        }, label="projection error ledger")
        raise
    _update_status(run, receipt, required, name, "APPLIED", error=None)
    return result, False


def load_projection_manifest(run: Path, receipt_id: str) -> dict[str, Any] | None:
    path = projection_path(run, receipt_id)
    return _load_manifest(path) if path.exists() else None


def _update_status(
    run: Path, receipt: Mapping[str, Any], required: Sequence[str], name: str,
    status: str, *, error: str | None,
) -> dict[str, Any]:
    if status not in PROJECTION_STATES:
        raise ProjectionError("projection status is invalid")
    path = projection_path(run, _identifier(receipt.get("receipt_id"), "receipt_id"))
    with state_lock(run):
        payload = _load_manifest(path) if path.exists() else _new_manifest(receipt, required)
        row = payload.get("projections", {}).get(name)
        if not isinstance(row, dict):
            raise ProjectionError(f"projection {name!r} is not required by this receipt")
        if row.get("status") in {"APPLIED", "NOT_REQUIRED"}:
            return payload
        row.update({
            "status": status,
            "attempts": int(row.get("attempts", 0)) + 1,
            "last_error": error[:2000] if error else None,
            "updated_at": utc_now(),
        })
        atomic_json(path, payload)
        return payload


def _new_manifest(receipt: Mapping[str, Any], required: Sequence[str]) -> dict[str, Any]:
    names = _projection_names(required)
    return {
        "schema_version": PROJECTION_SCHEMA_VERSION,
        "receipt_id": receipt.get("receipt_id"), "run_id": receipt.get("run_id"),
        "challenge_id": receipt.get("challenge_id"),
        "input_fingerprint": receipt.get("input_fingerprint"),
        "target_revision": receipt.get("target_revision"),
        "projections": {
            name: {"status": "PENDING", "attempts": 0, "last_error": None,
                   "updated_at": receipt.get("created_at")}
            for name in names
        },
    }


def _load_manifest(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ProjectionError("projection manifest is missing or unsafe")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProjectionError("projection manifest is malformed") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != PROJECTION_SCHEMA_VERSION:
        raise ProjectionError("projection manifest schema is unsupported")
    rows = payload.get("projections")
    if not isinstance(rows, dict) or any(
        not isinstance(row, dict) or row.get("status") not in PROJECTION_STATES
        for row in rows.values()
    ):
        raise ProjectionError("projection manifest rows are malformed")
    return payload


def _projection_names(values: Sequence[str]) -> list[str]:
    if isinstance(values, (str, bytes)):
        raise ProjectionError("required projections must be an array")
    names = []
    for value in values:
        name = _identifier(value, "projection")
        if name not in names:
            names.append(name)
    if not names:
        raise ProjectionError("receipt must declare at least one projection")
    return names


def _identifier(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 128 or any(char in text for char in "/\\\0\r\n"):
        raise ProjectionError(f"{field} is invalid")
    return text


def _projection_failpoint(name: str, phase: str, receipt: Mapping[str, Any]) -> None:
    """Private no-op seam used only by fault-injection tests."""
