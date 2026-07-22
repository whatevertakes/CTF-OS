"""Fresh attempt identity separated from deterministic challenge snapshots."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any


ATTEMPT_SCHEMA_VERSION = 1
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


class AttemptError(ValueError):
    pass


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def safe_attempt_id(value: str | None = None) -> str:
    attempt_id = value or f"attempt-{os.urandom(16).hex()}"
    if not _SAFE_ID.fullmatch(attempt_id):
        raise AttemptError("attempt_id must be a safe 1-128 character identifier")
    return attempt_id


def tree_digest(root: Path) -> str:
    """Digest a prepared input tree without following links or using mtimes."""

    if root.is_symlink() or not root.is_dir():
        return hashlib.sha256(b"MISSING").hexdigest()
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise AttemptError(f"challenge snapshot contains a symlink: {relative}")
        if path.is_dir():
            rows.append({"path": relative, "type": "directory"})
        elif path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            rows.append({
                "path": relative, "type": "file", "size": path.stat().st_size,
                "sha256": digest.hexdigest(),
            })
        else:
            raise AttemptError(f"challenge snapshot contains a non-regular entry: {relative}")
    return sha256_json(rows)


def challenge_snapshot_material(
    workspace: Path,
    challenge: object,
    *,
    input_fingerprint: str,
    target_revision: int,
    transformation_seed: str | int | None = None,
    challenge_metadata: Mapping[str, Any] | None = None,
    local_target_image_digest: str | None = None,
) -> dict[str, Any]:
    metadata = dict(challenge_metadata or {})
    if not metadata:
        metadata = {
            key: getattr(challenge, key, None)
            for key in (
                "id", "key", "category", "name", "description", "hint", "input_profile",
                "remotes",
            )
        }
    flag_metadata = {
        "flag_format_sha256": hashlib.sha256(
            str(getattr(challenge, "flag_format", "") or "").encode()
        ).hexdigest(),
        "flag_pattern_sha256": hashlib.sha256(
            str(getattr(challenge, "flag_pattern", "") or "").encode()
        ).hexdigest(),
    }
    return {
        "prepared_input_tree_digest": tree_digest(workspace / "input"),
        "challenge_metadata_digest": sha256_json(metadata),
        "input_fingerprint": input_fingerprint,
        "authorized_target_revision": target_revision,
        "flag_metadata": flag_metadata,
        "local_target_image_digest": local_target_image_digest,
        "transformation_seed": "NONE" if transformation_seed is None else str(transformation_seed),
    }


def challenge_snapshot_digest(*args: Any, **kwargs: Any) -> str:
    return sha256_json(challenge_snapshot_material(*args, **kwargs))


def challenge_instance_id(
    *,
    challenge_id: str,
    input_fingerprint: str,
    target_revision: int,
    challenge_snapshot_digest: str,
    transformation_seed: str | int | None = None,
) -> str:
    digest = sha256_json({
        "challenge_id": challenge_id,
        "input_fingerprint": input_fingerprint,
        "target_revision": target_revision,
        "challenge_snapshot_digest": challenge_snapshot_digest,
        "transformation_seed": "NONE" if transformation_seed is None else str(transformation_seed),
    })
    return f"ci-{digest[:32]}"


def run_id_for_attempt(challenge_instance_id: str, attempt_id: str) -> str:
    safe_attempt_id(attempt_id)
    return "run-" + sha256_json({
        "challenge_instance_id": challenge_instance_id, "attempt_id": attempt_id,
    })[:32]


def legacy_identity(
    *, challenge_id: str, input_fingerprint: str, target_revision: int,
    snapshot_digest: str,
) -> dict[str, Any]:
    instance = challenge_instance_id(
        challenge_id=challenge_id, input_fingerprint=input_fingerprint,
        target_revision=target_revision, challenge_snapshot_digest=snapshot_digest,
    )
    marker = "legacy-" + sha256_json({
        "challenge_instance_id": instance, "legacy": True,
    })[:24]
    return {
        "challenge_instance_id": instance, "attempt_id": marker,
        "legacy_identity": True,
    }
