"""Signed, read-only benchmark preregistration lock verification."""

from __future__ import annotations

from collections.abc import Mapping
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .attempts import canonical_json


LOCK_SCHEMA_VERSION = 1
REQUIRED_LOCK_FIELDS = frozenset({
    "schema_version", "experiment_id", "candidate_git_commit", "clean_worktree_required",
    "canonical_arm_configuration", "configuration_digest", "challenge_archive_sha256",
    "challenge_snapshot_digest", "transformation_seed", "target_image_digest",
    "tool_image_digest", "expected_flag_hash", "flag_pattern", "requested_model",
    "runtime_model_observation_policy", "cli_build_hash", "surface", "reasoning",
    "host_requirements", "network_profile", "time_limit_seconds",
    "maximum_model_concurrency", "randomization_seed", "created_at", "signing_key_id",
    "schedule_digest",
})
ARM_CONFIGURATION = {
    "A": {"mode": "plain-sol", "child_count": 0, "orchestration": False},
    "B": {"mode": "sol-only", "child_count": 0, "orchestration": True},
    "C": {"mode": "fixed-race", "child_count": 3, "replacement_limit": 0},
    "D": {"mode": "adaptive-race", "child_count_range": [0, 3], "replacement_limit": 1},
}
NETWORK_PROFILE = {
    "target": "local-replay", "rtt_ms": 30, "packet_loss_percent": 0.1,
    "bandwidth_mbit_per_second": 100, "dns_policy": "IDENTICAL",
    "outbound_policy": "DENY_IDENTICAL",
}
HOST_REQUIREMENTS = {
    "minimum_vcpu": 16, "minimum_ram_gib": 64, "minimum_free_ssd_gib": 200,
    "docker_server": "Linux/amd64", "gpu": "DISABLED_MINIMUM_SET",
}
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|secret|credential|access.?token|api.?token|api.?key|token)", re.I,
)
_PERSONAL_PATH = re.compile(r"(?:/home/[^/]+|/Users/[^/]+|[A-Za-z]:\\Users\\[^\\]+)")


class BenchmarkLockError(ValueError):
    pass


def configuration_digest(configuration: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(dict(configuration))).hexdigest()


def build_lock(**values: Any) -> dict[str, Any]:
    payload = dict(values)
    payload.setdefault("schema_version", LOCK_SCHEMA_VERSION)
    payload.setdefault("canonical_arm_configuration", json.loads(json.dumps(ARM_CONFIGURATION)))
    payload.setdefault(
        "configuration_digest",
        configuration_digest(payload["canonical_arm_configuration"]),
    )
    payload.setdefault("host_requirements", dict(HOST_REQUIREMENTS))
    payload.setdefault("network_profile", dict(NETWORK_PROFILE))
    payload.setdefault("time_limit_seconds", 2700)
    payload.setdefault("maximum_model_concurrency", 4)
    validate_lock_payload(payload)
    return payload


def write_signed_lock(
    lock_path: Path,
    signature_path: Path,
    payload: Mapping[str, Any],
    private_key: Ed25519PrivateKey | bytes | Path,
    *,
    make_read_only: bool = True,
) -> dict[str, Any]:
    """Development/preregistration helper; the private key is never copied."""

    validate_lock_payload(payload)
    if _inside_output(lock_path) or _inside_output(signature_path):
        raise BenchmarkLockError("benchmark lock and signature must live outside challenge output")
    key = _private_key(private_key)
    data = canonical_json(dict(payload))
    digest = hashlib.sha256(data).hexdigest()
    signature = key.sign(data)
    _exclusive_write(lock_path, data + b"\n", mode=0o444 if make_read_only else 0o600)
    envelope = {
        "schema_version": 1, "algorithm": "Ed25519",
        "signing_key_id": payload["signing_key_id"], "lock_digest": digest,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    _exclusive_write(
        signature_path, canonical_json(envelope) + b"\n",
        mode=0o444 if make_read_only else 0o600,
    )
    return {"lock_digest": digest, "signature_path": str(signature_path)}


def verify_benchmark_lock(
    lock_path: Path,
    signature_path: Path,
    public_keys: Mapping[str, Ed25519PublicKey | bytes | Path],
    *,
    expected_commit: str | None = None,
    worktree_clean: bool | None = None,
    expected_challenge_snapshot_digest: str | None = None,
    expected_target_image_digest: str | None = None,
    expected_tool_image_digest: str | None = None,
) -> dict[str, Any]:
    for path, label in ((lock_path, "benchmark lock"), (signature_path, "benchmark signature")):
        _validate_read_only_regular(path, label)
        if _inside_output(path):
            raise BenchmarkLockError(f"{label} must live outside challenge output")
    raw = lock_path.read_bytes()
    payload = _strict_json(raw, "benchmark lock")
    canonical = canonical_json(payload) + b"\n"
    if raw != canonical:
        raise BenchmarkLockError("benchmark lock must be exact canonical JSON with one trailing newline")
    validate_lock_payload(payload)
    envelope_raw = signature_path.read_bytes()
    envelope = _strict_json(envelope_raw, "benchmark signature")
    if envelope_raw != canonical_json(envelope) + b"\n":
        raise BenchmarkLockError("benchmark signature must be canonical JSON")
    digest = hashlib.sha256(canonical_json(payload)).hexdigest()
    if envelope.get("algorithm") != "Ed25519" or envelope.get("lock_digest") != digest:
        raise BenchmarkLockError("benchmark signature envelope digest or algorithm is invalid")
    key_id = str(payload["signing_key_id"])
    if envelope.get("signing_key_id") != key_id or key_id not in public_keys:
        raise BenchmarkLockError("benchmark signing key is unknown or inconsistent")
    try:
        signature = base64.b64decode(str(envelope.get("signature") or ""), validate=True)
        _public_key(public_keys[key_id]).verify(signature, canonical_json(payload))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise BenchmarkLockError("benchmark lock Ed25519 signature is invalid") from exc
    if expected_commit is not None and payload["candidate_git_commit"] != expected_commit:
        raise BenchmarkLockError("benchmark candidate commit does not match the current environment")
    if payload["clean_worktree_required"] and worktree_clean is not True:
        raise BenchmarkLockError("benchmark start requires an explicitly observed clean worktree")
    for field, expected in (
        ("challenge_snapshot_digest", expected_challenge_snapshot_digest),
        ("target_image_digest", expected_target_image_digest),
        ("tool_image_digest", expected_tool_image_digest),
    ):
        if expected is not None and payload[field] != expected:
            raise BenchmarkLockError(f"benchmark {field} mismatch")
    return {"payload": payload, "lock_digest": digest, "signature_valid": True}


def validate_lock_payload(payload: Mapping[str, Any]) -> None:
    missing = REQUIRED_LOCK_FIELDS.difference(payload)
    if missing:
        raise BenchmarkLockError(f"benchmark lock missing fields: {sorted(missing)}")
    if payload.get("schema_version") != LOCK_SCHEMA_VERSION:
        raise BenchmarkLockError("benchmark lock schema_version is unsupported")
    if not _HEX40.fullmatch(str(payload.get("candidate_git_commit") or "")):
        raise BenchmarkLockError("candidate_git_commit must be exact lowercase 40-hex")
    if payload.get("clean_worktree_required") is not True:
        raise BenchmarkLockError("production benchmark lock must require a clean worktree")
    arm_config = payload.get("canonical_arm_configuration")
    if not isinstance(arm_config, Mapping) or set(arm_config) != {"A", "B", "C", "D"}:
        raise BenchmarkLockError("canonical arm configuration must define A/B/C/D")
    if payload.get("configuration_digest") != configuration_digest(arm_config):
        raise BenchmarkLockError("arm configuration digest mismatch")
    for field in (
        "challenge_archive_sha256", "challenge_snapshot_digest", "expected_flag_hash",
        "cli_build_hash",
        "schedule_digest",
    ):
        if not _HEX64.fullmatch(str(payload.get(field) or "")):
            raise BenchmarkLockError(f"{field} must be exact lowercase SHA-256")
    for field in ("target_image_digest", "tool_image_digest"):
        value = str(payload.get(field) or "")
        if not _IMAGE_DIGEST.fullmatch(value):
            raise BenchmarkLockError(
                f"{field} must be a resolved content-addressed sha256 digest; mutable tags are forbidden"
            )
    if payload.get("time_limit_seconds") != 2700:
        raise BenchmarkLockError("benchmark time limit must be 2700 seconds")
    if payload.get("maximum_model_concurrency") != 4:
        raise BenchmarkLockError("benchmark maximum model concurrency must be 4")
    if payload.get("host_requirements") != HOST_REQUIREMENTS:
        raise BenchmarkLockError("benchmark host requirements do not match the preregistered minimum")
    if payload.get("network_profile") != NETWORK_PROFILE:
        raise BenchmarkLockError("benchmark network profile is not the fixed matched profile")
    _reject_sensitive(payload)


def _reject_sensitive(value: Any, *, key: str = "") -> None:
    if key and _SENSITIVE_KEY.search(key):
        raise BenchmarkLockError(f"benchmark lock contains a forbidden sensitive field: {key}")
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            _reject_sensitive(child, key=str(child_key))
    elif isinstance(value, list):
        for child in value:
            _reject_sensitive(child, key=key)
    elif isinstance(value, str) and _PERSONAL_PATH.search(value):
        raise BenchmarkLockError("benchmark lock contains a personal host path")


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise BenchmarkLockError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BenchmarkLockError(f"{label} is malformed JSON") from exc
    if not isinstance(value, dict):
        raise BenchmarkLockError(f"{label} must be a JSON object")
    return value


def _validate_read_only_regular(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise BenchmarkLockError(f"{label} must be a regular non-symlink file")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
        raise BenchmarkLockError(f"{label} must be read-only")


def _inside_output(path: Path) -> bool:
    return "output" in path.resolve(strict=False).parts


def _private_key(value: Ed25519PrivateKey | bytes | Path) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    data = value.read_bytes() if isinstance(value, Path) else value
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise BenchmarkLockError("private signing key must be Ed25519")
    return key


def _public_key(value: Ed25519PublicKey | bytes | Path) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        return value
    data = value.read_bytes() if isinstance(value, Path) else value
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise BenchmarkLockError("public verification key must be Ed25519")
    return key


def _exclusive_write(path: Path, data: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise BenchmarkLockError(f"refusing to overwrite benchmark preregistration file: {path}")
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
