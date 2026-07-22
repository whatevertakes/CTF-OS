"""Challenge-scoped credential, cloud mutation, and AI artifact guards."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .workspace import utc_now


class ChallengeScopeError(ValueError):
    pass


def save_challenge_secret(
    worker_root: Path, *, branch_id: str, name: str, value: str,
    provenance: str, challenge_id: str,
) -> dict[str, Any]:
    if provenance != "challenge-provided":
        raise ChallengeScopeError("personal, ambient, or team-member credentials are forbidden")
    if worker_root.name != branch_id or worker_root.parent.name != "workers":
        raise ChallengeScopeError("secret storage must be the matching worker-private directory")
    if not name.replace("_", "").replace("-", "").isalnum() or len(name) > 64:
        raise ChallengeScopeError("invalid challenge secret name")
    if not value or len(value) > 16_384:
        raise ChallengeScopeError("challenge secret value is empty or too large")
    secret_root = worker_root / "private-secrets"
    if secret_root.is_symlink():
        raise ChallengeScopeError("worker secret directory must not be a symlink")
    secret_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = secret_root / name
    descriptor = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
    return {
        "name": name, "path": str(path), "branch_id": branch_id,
        "challenge_id": challenge_id, "provenance": provenance,
        "sha256": hashlib.sha256(value.encode()).hexdigest(),
        "value": "[REDACTED]", "created_at": utc_now(),
    }


def remove_challenge_secrets(worker_root: Path) -> dict[str, Any]:
    root = worker_root / "private-secrets"
    removed = []
    if root.is_dir() and not root.is_symlink():
        for path in root.iterdir():
            if path.is_file() and not path.is_symlink():
                path.unlink()
                removed.append(path.name)
        root.rmdir()
    return {"removed": sorted(removed)}


def record_cloud_mutation(
    worker_root: Path, *, challenge_id: str, branch_id: str,
    account_scope: str, declared_scopes: Sequence[str], action: str,
    resource: str, result: str,
) -> dict[str, Any]:
    if worker_root.name != branch_id or worker_root.parent.name != "workers":
        raise ChallengeScopeError("cloud mutation ledger must be branch-private")
    if account_scope not in declared_scopes:
        raise ChallengeScopeError("cloud account/project/tenant is outside declared challenge scope")
    forbidden = ("delete-all", "destroy-account", "wipe-tenant", "disable-logging")
    if any(token in action.casefold() for token in forbidden):
        raise ChallengeScopeError("unbounded destructive cloud mutation is forbidden")
    payload = {
        "event_id": hashlib.sha256(
            json.dumps([challenge_id, branch_id, account_scope, action, resource, result], separators=(",", ":")).encode()
        ).hexdigest()[:24],
        "challenge_id": challenge_id, "branch_id": branch_id,
        "account_scope": account_scope, "action": action, "resource": resource,
        "result": result, "created_at": utc_now(),
    }
    _append_jsonl(worker_root / "cloud-mutations.jsonl", payload)
    return payload


def validate_ai_artifact(
    path: Path, *, inside_sandbox: bool, trust_remote_code: bool = False,
    allowed_size_bytes: int = 20 * 1024**3,
) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ChallengeScopeError("AI artifact is missing or unsafe")
    if path.stat().st_size > allowed_size_bytes:
        raise ChallengeScopeError("AI artifact exceeds the challenge model size budget")
    unsafe_format = path.suffix.casefold() in {".pkl", ".pickle", ".joblib", ".pt", ".pth"}
    if unsafe_format and not inside_sandbox:
        raise ChallengeScopeError("unsafe model deserialization is permitted only inside the solver sandbox")
    if trust_remote_code:
        raise ChallengeScopeError("trust_remote_code=True is forbidden")
    return {
        "path": str(path), "size": path.stat().st_size, "unsafe_format": unsafe_format,
        "sandbox_required": unsafe_format, "validated_at": utc_now(),
    }


def validate_model_download(
    url: str, *, allowed_domains: Sequence[str], expected_size_bytes: int,
    size_budget_bytes: int = 20 * 1024**3,
) -> dict[str, Any]:
    parsed = urlsplit(url)
    domains = {domain.casefold().rstrip(".") for domain in allowed_domains}
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ChallengeScopeError("public challenge models require a credential-free HTTPS URL")
    host = parsed.hostname.casefold().rstrip(".")
    if host not in domains:
        raise ChallengeScopeError("model host is outside the challenge allowlist")
    if expected_size_bytes <= 0 or expected_size_bytes > size_budget_bytes:
        raise ChallengeScopeError("model download exceeds the configured size budget")
    return {
        "url": url, "host": host, "expected_size_bytes": expected_size_bytes,
        "size_budget_bytes": size_budget_bytes, "sandbox_download_required": True,
    }


def _append_jsonl(path: Path, payload: Mapping[str, Any]) -> None:
    if path.is_symlink():
        raise ChallengeScopeError("mutation ledger must not be a symlink")
    descriptor = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(dict(payload), sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
