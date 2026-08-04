"""Read-only, operator-only verification of one canonical flag candidate.

The verifier intentionally accepts a candidate ID, never a candidate value.
It reads the canonical value from ``state.json`` through the read-only store,
compares an in-memory SHA-256 commitment from a private reference, and emits
only ``candidate_id``, ``matched``, and ``error``.  The canonical operator
surface is ``ctfos benchmark ctftiny-verify``; ``main`` preserves the narrow
compatibility script contract.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from ctf_os.models import ChallengeIdentity
from ctf_os.store import StateStore


_CANDIDATE_ID = re.compile(r"C-[A-Za-z0-9_.:-]{1,255}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_REFERENCE_MAX_BYTES = 64 * 1024
_CATEGORY_PREFIXES = {
    "crypto": "cry",
    "rev": "rev",
    "reversing": "rev",
}


class _VerifierFailure(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _ArgumentFailure(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise _ArgumentFailure


@dataclass(frozen=True, slots=True)
class VerificationResult:
    candidate_id: str | None
    matched: bool | None
    error: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "matched": self.matched,
            "error": self.error,
        }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _private_root(workspace_root: Path) -> Path:
    return (
        workspace_root
        / ".ctfos"
        / "benchmarks"
        / "external-pilots"
        / "private"
    ).resolve(strict=True)


def _read_private_reference(
    workspace_root: Path,
    reference_path: Path,
) -> dict[str, Any]:
    try:
        private_root = _private_root(workspace_root)
        requested = Path(os.path.abspath(reference_path))
        resolved = reference_path.resolve(strict=True)
        resolved.relative_to(private_root)
    except (OSError, RuntimeError, ValueError) as error:
        raise _VerifierFailure("private_reference_scope") from error
    if requested != resolved:
        raise _VerifierFailure("private_reference_scope")

    flags = os.O_RDONLY | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as error:
        raise _VerifierFailure("private_reference_unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise _VerifierFailure("private_reference_unavailable")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise _VerifierFailure("private_reference_permissions")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise _VerifierFailure("private_reference_permissions")
        if not 1 <= metadata.st_size <= _REFERENCE_MAX_BYTES:
            raise _VerifierFailure("private_reference_invalid")
        payload = bytearray()
        while len(payload) <= _REFERENCE_MAX_BYTES:
            remaining = _REFERENCE_MAX_BYTES + 1 - len(payload)
            chunk = os.read(descriptor, min(8192, remaining))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) != metadata.st_size or len(payload) > _REFERENCE_MAX_BYTES:
            raise _VerifierFailure("private_reference_invalid")
    finally:
        os.close(descriptor)

    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeError, ValueError, TypeError) as error:
        raise _VerifierFailure("private_reference_invalid") from error
    if not isinstance(document, dict):
        raise _VerifierFailure("private_reference_invalid")
    return document


def _expected_commitment(
    document: dict[str, Any],
    identity: ChallengeIdentity,
) -> str:
    private_value = document.get("private_value")
    task_id = document.get("task_id")
    if (
        document.get("benchmark") != "CTFTiny"
        or not isinstance(private_value, dict)
        or not isinstance(task_id, str)
        or private_value.get("type") != "string"
        or private_value.get("value_embedded") is not False
        or private_value.get("json_pointer") != "/flag"
    ):
        raise _VerifierFailure("private_reference_invalid")
    expected = private_value.get("text_sha256")
    if not isinstance(expected, str) or _SHA256.fullmatch(expected) is None:
        raise _VerifierFailure("private_reference_invalid")

    parts = task_id.split("/")
    prefix = _CATEGORY_PREFIXES.get(identity.category.casefold())
    if (
        prefix is None
        or len(parts) != 3
        or parts[0] != prefix
        or parts[-1] != identity.challenge_id
    ):
        raise _VerifierFailure("reference_identity_mismatch")
    return expected


def verify_candidate(
    *,
    workspace_root: Path,
    identity: ChallengeIdentity,
    candidate_id: str,
    reference_path: Path,
) -> VerificationResult:
    """Verify one canonical candidate without mutating state or exposing values."""

    safe_id = candidate_id if _CANDIDATE_ID.fullmatch(candidate_id) else None
    if safe_id is None:
        return VerificationResult(None, None, "invalid_candidate_id")
    try:
        root = workspace_root.expanduser().resolve(strict=True)
        reference = _read_private_reference(root, reference_path)
        expected = _expected_commitment(reference, identity)
        store = StateStore.open_read_only(root)
        state = store.load(identity, recover=False)
        matches = [item for item in state.candidates if item.id == safe_id]
        if len(matches) != 1:
            raise _VerifierFailure("candidate_not_found")
        actual = hashlib.sha256(matches[0].value.encode("utf-8")).hexdigest()
        return VerificationResult(
            safe_id,
            hmac.compare_digest(actual, expected),
            None,
        )
    except _VerifierFailure as error:
        return VerificationResult(safe_id, None, error.code)
    except Exception:
        return VerificationResult(safe_id, None, "state_unavailable")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description="Operator-only CTFTiny candidate verifier")
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--contest", required=True)
    parser.add_argument("--category", required=True)
    parser.add_argument("--challenge", required=True)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--reference", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        result = verify_candidate(
            workspace_root=args.workspace_root,
            identity=ChallengeIdentity(
                args.contest,
                args.category,
                args.challenge,
            ),
            candidate_id=args.candidate_id,
            reference_path=args.reference,
        )
    except (_ArgumentFailure, ValueError):
        result = VerificationResult(None, None, "invalid_arguments")
    print(json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":")))
    if result.error is not None:
        return 2
    return 0 if result.matched else 1


__all__ = ["VerificationResult", "main", "verify_candidate"]
