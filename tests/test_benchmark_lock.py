from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ctf_os.benchmark_lock import (
    ARM_CONFIGURATION, BenchmarkLockError, HOST_REQUIREMENTS, NETWORK_PROFILE,
    build_lock, verify_benchmark_lock, write_signed_lock,
)


def _payload(**changes):
    values = {
        "experiment_id": "third-surgery", "candidate_git_commit": "a" * 40,
        "clean_worktree_required": True, "challenge_archive_sha256": "b" * 64,
        "challenge_snapshot_digest": "c" * 64, "transformation_seed": "NONE",
        "target_image_digest": "sha256:" + "d" * 64,
        "tool_image_digest": "sha256:" + "e" * 64,
        "expected_flag_hash": "f" * 64, "flag_pattern": r"CTF\{[^}]+\}",
        "requested_model": "model", "runtime_model_observation_policy": "REQUIRED",
        "cli_build_hash": "1" * 64, "surface": "Sol", "reasoning": "high",
        "randomization_seed": "registered", "created_at": "2026-07-20T00:00:00Z",
        "signing_key_id": "ephemeral-test", "schedule_digest": "2" * 64,
    }
    values.update(changes)
    return build_lock(**values)


def _signed(tmp_path: Path, payload=None):
    key = Ed25519PrivateKey.generate(); lock = tmp_path / "BENCHMARK_LOCK.json"; sig = tmp_path / "BENCHMARK_LOCK.sig"
    write_signed_lock(lock, sig, payload or _payload(), key)
    return lock, sig, key.public_key()


def test_benchmark_cannot_start_with_unsigned_lock(tmp_path: Path) -> None:
    lock = tmp_path / "BENCHMARK_LOCK.json"; lock.write_text(json.dumps(_payload())); lock.chmod(0o444)
    with pytest.raises(BenchmarkLockError):
        verify_benchmark_lock(lock, tmp_path / "missing.sig", {"ephemeral-test": Ed25519PrivateKey.generate().public_key()})


def test_benchmark_cannot_start_with_writable_or_symlink_lock(tmp_path: Path) -> None:
    lock, sig, public = _signed(tmp_path); lock.chmod(0o644)
    with pytest.raises(BenchmarkLockError, match="read-only"):
        verify_benchmark_lock(lock, sig, {"ephemeral-test": public})
    lock.chmod(0o444); link = tmp_path / "link.json"; link.symlink_to(lock)
    with pytest.raises(BenchmarkLockError, match="non-symlink"):
        verify_benchmark_lock(link, sig, {"ephemeral-test": public})


def test_invalid_signature_is_rejected(tmp_path: Path) -> None:
    lock, sig, _public = _signed(tmp_path)
    with pytest.raises(BenchmarkLockError, match="signature"):
        verify_benchmark_lock(lock, sig, {"ephemeral-test": Ed25519PrivateKey.generate().public_key()})


def test_every_attempt_copies_exact_lock_digest(tmp_path: Path) -> None:
    lock, sig, public = _signed(tmp_path)
    result = verify_benchmark_lock(lock, sig, {"ephemeral-test": public}, worktree_clean=True)
    assert len(result["lock_digest"]) == 64 and result["signature_valid"] is True


def test_dirty_commit_is_rejected(tmp_path: Path) -> None:
    lock, sig, public = _signed(tmp_path)
    with pytest.raises(BenchmarkLockError, match="clean worktree"):
        verify_benchmark_lock(lock, sig, {"ephemeral-test": public}, worktree_clean=False)


def test_mutable_image_tag_without_resolved_digest_is_rejected() -> None:
    with pytest.raises(BenchmarkLockError, match="content-addressed"):
        _payload(tool_image_digest="ctf-os-sandbox:latest")


def test_challenge_snapshot_mismatch_is_rejected(tmp_path: Path) -> None:
    lock, sig, public = _signed(tmp_path)
    with pytest.raises(BenchmarkLockError, match="snapshot"):
        verify_benchmark_lock(lock, sig, {"ephemeral-test": public},
                              worktree_clean=True, expected_challenge_snapshot_digest="0" * 64)


def test_arm_configuration_digest_mismatch_is_rejected() -> None:
    payload = _payload(); payload["canonical_arm_configuration"]["C"]["child_count"] = 2
    with pytest.raises(BenchmarkLockError, match="configuration digest"):
        build_lock(**payload)


def test_lock_contains_no_credentials_or_personal_host_paths() -> None:
    with pytest.raises(BenchmarkLockError, match="sensitive"):
        _payload(api_token="secret")
    with pytest.raises(BenchmarkLockError, match="personal host path"):
        _payload(surface="/home/alice/private")
