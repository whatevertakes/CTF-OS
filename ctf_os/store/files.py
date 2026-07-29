"""Filesystem-backed, single-writer challenge state store."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any, TypeVar

from ctf_os.candidates import candidate_value_is_valid
from ctf_os.engine.state_machine import (
    TransitionEvidence,
    validate_transition,
)
from ctf_os.models import (
    CURRENT_SCHEMA_VERSION,
    ArtifactReference,
    Budget,
    CandidateStatus,
    CandidateTier,
    ChallengeIdentity,
    ChallengeState,
    ChallengeStatus,
    ClosureBundle,
    ClosureCompleteness,
    FlagCandidate,
    GoalStatus,
    SessionStatus,
    SubmissionOverride,
    SubmissionReference,
    SubmissionStatus,
    new_challenge_state,
    utc_now,
)
from ctf_os.schema import (
    BOARD_VIEW_SCHEMA_VERSION,
    CANDIDATE_INTENT_SCHEMA_VERSION,
    CONTEST_MANIFEST_SCHEMA_VERSION,
    EVENT_RECORD_SCHEMA_VERSION,
    RUN_ENVELOPE_SCHEMA_VERSION,
    SUBMISSION_INTENT_SCHEMA_VERSION,
    SUBMISSION_LEDGER_RECORD_SCHEMA_VERSION,
    STATE_SCHEMA_VERSION,
    WORKER_RESULT_SCHEMA_VERSION,
)
from ctf_os.store.atomic import (
    append_json_line,
    atomic_write_bytes,
    atomic_write_json,
    atomic_write_text,
    canonical_json_bytes,
    read_json,
    strict_json_loads,
)
from ctf_os.store.locks import ChallengeLock, FileLock
from ctf_os.store.upgrades import upgrade_state, validate_state_protocol_shape
from ctf_os.store.views import (
    board_entry,
    render_board_markdown,
    render_current_markdown,
)


class StateStoreError(RuntimeError):
    """Base class for expected state-store errors."""


class MigrationInProgress(StateStoreError):
    """Canonical mutation is blocked by a schema migration marker."""


class InvalidIdentity(StateStoreError, ValueError):
    """Raised when an identity component is unsafe as a literal directory."""


class StateNotFound(StateStoreError, FileNotFoundError):
    """Raised when a challenge has no durable state."""


class StateAlreadyExists(StateStoreError, FileExistsError):
    """Raised when a non-idempotent create targets an existing challenge."""


class CorruptStateError(StateStoreError):
    """Raised when neither the current nor previous state is readable."""


class RevisionConflict(StateStoreError):
    """Raised when a writer used a stale state revision."""

    def __init__(self, expected: int, actual: int) -> None:
        super().__init__(
            f"stale state revision: expected {expected}, current is {actual}"
        )
        self.expected = expected
        self.actual = actual


class ArtifactValidationError(StateStoreError, ValueError):
    """Raised when an artifact path or digest does not match its reference."""


class WorkerResultValidationError(StateStoreError, ValueError):
    """Raised when a structured worker result cannot be trusted."""


@dataclass(frozen=True)
class ContestPaths:
    root: Path
    contest_json: Path
    board: Path
    submissions: Path
    submission_intents: Path
    runtime: Path
    challenges: Path


@dataclass(frozen=True)
class ChallengePaths:
    root: Path
    state: Path
    previous_state: Path
    events: Path
    lock: Path
    runtime: Path
    candidate_intents: Path
    context: Path
    current_context: Path
    context_history: Path
    runs: Path
    artifacts: Path
    knowledge: Path
    proof: Path
    exports: Path


@dataclass(frozen=True)
class RunPaths:
    root: Path
    request: Path
    result: Path
    validation: Path
    raw: Path


_T = TypeVar("_T")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_ALLOWED_ARTIFACT_ROOTS = frozenset(
    {"artifacts", "runs", "proof", "knowledge"}
)
_CANDIDATE_INTENT_LIMIT = 1024
_CANDIDATE_INTENT_VALUE_BYTES_LIMIT = 256 * 1024
_CANDIDATE_INTENT_FILE_LIMIT_BYTES = 2 * 1024 * 1024
_CANDIDATE_SOURCE_LIMIT_BYTES = 4096
_SUBMISSION_LEDGER_RECOVERY_LIMIT_BYTES = 16 * 1024 * 1024
_SUBMISSION_INTENT_RECOVERY_LIMIT_BYTES = 16 * 1024 * 1024
MAX_CANONICAL_STATE_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024 * 1024


def _validate_component(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise InvalidIdentity(f"{label} must be a string")
    if not value or not value.strip():
        raise InvalidIdentity(f"{label} cannot be empty")
    if len(value.encode("utf-8")) > 255:
        raise InvalidIdentity(f"{label} must be at most 255 UTF-8 bytes")
    if value in {".", ".."}:
        raise InvalidIdentity(f"{label} cannot be '.' or '..'")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise InvalidIdentity(f"{label} cannot contain control characters")
    if "/" in value or "\\" in value:
        raise InvalidIdentity(f"{label} cannot contain a path separator")
    if Path(value).is_absolute() or PureWindowsPath(value).is_absolute():
        raise InvalidIdentity(f"{label} cannot be an absolute path")
    return value


def _identity(
    contest: str | ChallengeIdentity | ChallengeState,
    category: str | None = None,
    challenge_id: str | None = None,
) -> ChallengeIdentity:
    if isinstance(contest, ChallengeState):
        identity = contest.identity
    elif isinstance(contest, ChallengeIdentity):
        identity = contest
    else:
        if category is None or challenge_id is None:
            raise TypeError(
                "category and challenge_id are required with a contest string"
            )
        identity = ChallengeIdentity(contest, category, challenge_id)
    return ChallengeIdentity(
        _validate_component(identity.contest_id, "contest_id"),
        _validate_component(identity.category, "category"),
        _validate_component(identity.challenge_id, "challenge_id"),
    )


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _read_bounded_regular(path: Path, *, maximum_bytes: int) -> bytes:
    """Read one stable regular file without following a terminal symlink."""

    flags = os.O_RDONLY | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CorruptStateError(f"state is not a regular file: {path}")
        if before.st_size > maximum_bytes:
            raise CorruptStateError(
                f"state exceeds {maximum_bytes} bytes: {path}"
            )
        chunks: list[bytes] = []
        total = 0
        while total <= maximum_bytes:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, maximum_bytes + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        if total > maximum_bytes:
            raise CorruptStateError(
                f"state exceeds {maximum_bytes} bytes: {path}"
            )
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or total != after.st_size:
            raise CorruptStateError(f"state changed while being read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _reject_symlink_chain(root: Path, relative: Path) -> None:
    current = root
    for component in relative.parts:
        current = current / component
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            raise ArtifactValidationError(
                f"artifact does not exist: {relative.as_posix()}"
            ) from None
        if stat.S_ISLNK(mode):
            raise ArtifactValidationError(
                f"artifact path contains a symlink: {relative.as_posix()}"
            )


def _resolve_artifact_path(
    challenge_root: Path,
    reference: ArtifactReference,
    *,
    allowed_roots: frozenset[str] | set[str] | None = None,
) -> Path:
    relative = Path(reference.path)
    if (
        relative.is_absolute()
        or PureWindowsPath(reference.path).is_absolute()
        or "\\" in reference.path
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ArtifactValidationError(
            f"artifact path must be a normalized relative path: "
            f"{reference.path!r}"
        )
    allowed = _ALLOWED_ARTIFACT_ROOTS if allowed_roots is None else allowed_roots
    if relative.parts[0] not in allowed:
        raise ArtifactValidationError(
            f"artifact path is outside allowed roots {sorted(allowed)}: "
            f"{reference.path!r}"
        )

    root = Path(challenge_root).resolve(strict=True)
    _reject_symlink_chain(root, relative)
    path = root / relative
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (FileNotFoundError, ValueError) as error:
        raise ArtifactValidationError(
            f"artifact escapes or is missing from challenge workspace: "
            f"{reference.path!r}"
        ) from error
    mode = resolved.stat().st_mode
    if not stat.S_ISREG(mode):
        raise ArtifactValidationError(
            f"artifact is not a regular file: {reference.path!r}"
        )
    return resolved


def validate_artifact(
    challenge_root: Path,
    artifact: ArtifactReference | Mapping[str, Any] | str,
    expected_sha256: str | None = None,
    *,
    allowed_roots: frozenset[str] | set[str] | None = None,
) -> Path:
    """Validate a regular artifact's containment and SHA-256 digest."""

    if isinstance(artifact, ArtifactReference):
        reference = artifact
    elif isinstance(artifact, Mapping):
        reference = ArtifactReference.from_dict(artifact)
    else:
        if expected_sha256 is None:
            raise TypeError("expected_sha256 is required with a path string")
        reference = ArtifactReference(
            id="artifact",
            path=str(artifact),
            sha256=expected_sha256,
        )
    if not _SHA256.fullmatch(reference.sha256):
        raise ArtifactValidationError(
            f"artifact {reference.id!r} has an invalid SHA-256 digest"
        )
    resolved = _resolve_artifact_path(
        challenge_root,
        reference,
        allowed_roots=allowed_roots,
    )
    actual = sha256_file(resolved)
    if actual.lower() != reference.sha256.lower():
        raise ArtifactValidationError(
            f"artifact {reference.id!r} hash mismatch: expected "
            f"{reference.sha256.lower()}, got {actual}"
        )
    if reference.size is not None and resolved.stat().st_size != reference.size:
        raise ArtifactValidationError(
            f"artifact {reference.id!r} size mismatch: expected "
            f"{reference.size}, got {resolved.stat().st_size}"
        )
    return resolved


class StateStore:
    """Manage the ``.ctfos`` filesystem tree under one workspace root."""

    def __init__(
        self,
        workspace_root: Path | str,
        *,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> None:
        if (
            isinstance(max_artifact_bytes, bool)
            or not isinstance(max_artifact_bytes, int)
            or max_artifact_bytes <= 0
        ):
            raise ValueError("max_artifact_bytes must be a positive integer")
        self.workspace_root = Path(workspace_root).resolve()
        self.root = self.workspace_root / ".ctfos"
        self.state_root = self.root
        self.contests_root = self.root / "contests"
        self.max_artifact_bytes = max_artifact_bytes
        self.last_view_errors: list[str] = []
        self._ensure_private_root()

    def _ensure_private_root(self) -> None:
        """Make all engine state and flag-bearing output non-traversable."""

        try:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.root, flags)
        except OSError as error:
            raise StateStoreError(
                f"state root must be a private directory: {self.root}"
            ) from error
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or opened.st_uid != os.geteuid()
            ):
                raise StateStoreError(
                    "state root must be owned by the current user"
                )
            os.fchmod(descriptor, 0o700)
        finally:
            os.close(descriptor)

    def assert_mutations_allowed(self) -> None:
        """Fail closed while an explicit workspace migration is transitional."""

        marker_path = self.root / "migration.json"
        try:
            marker = read_json(marker_path)
        except FileNotFoundError:
            return
        except (OSError, ValueError) as error:
            raise MigrationInProgress(
                "workspace migration marker is unreadable; mutations are blocked"
            ) from error
        if not isinstance(marker, Mapping):
            raise MigrationInProgress(
                "workspace migration marker is invalid; mutations are blocked"
            )
        status = marker.get("status")
        if status == "migrating":
            raise MigrationInProgress(
                "workspace state migration is in progress"
            )
        if status not in {
            "applied",
            "rolled_back",
            "failed",
            "failed_rolled_back",
        }:
            raise MigrationInProgress(
                "workspace migration marker has an unknown status; "
                "mutations are blocked"
            )

    @staticmethod
    def _serialized_state(state: ChallengeState) -> bytes:
        payload = canonical_json_bytes(state.to_dict())
        if len(payload) > MAX_CANONICAL_STATE_BYTES:
            raise WorkerResultValidationError(
                "canonical state JSON exceeds "
                f"{MAX_CANONICAL_STATE_BYTES} bytes"
            )
        return payload

    @staticmethod
    def _decode_state(
        payload: bytes,
        path: Path,
        *,
        expected: ChallengeIdentity | None = None,
    ) -> ChallengeState:
        raw = strict_json_loads(payload)
        if not isinstance(raw, Mapping):
            raise CorruptStateError(f"state root must be an object: {path}")
        validate_state_protocol_shape(raw)
        state = ChallengeState.from_dict(upgrade_state(raw))
        state.validate()
        if expected is not None and state.identity != expected:
            raise CorruptStateError(
                f"state identity {state.identity.key!r} does not match path "
                f"{expected.key!r}"
            )
        return state

    def contest_paths(self, contest_id: str) -> ContestPaths:
        contest_id = _validate_component(contest_id, "contest_id")
        root = self.contests_root / contest_id
        self._assert_contained(root)
        return ContestPaths(
            root=root,
            contest_json=root / "contest.json",
            board=root / "board.md",
            submissions=root / "submissions.jsonl",
            submission_intents=root / "runtime" / "submission-intents.json",
            runtime=root / "runtime",
            challenges=root / "challenges",
        )

    def challenge_paths(
        self,
        contest: str | ChallengeIdentity | ChallengeState,
        category: str | None = None,
        challenge_id: str | None = None,
    ) -> ChallengePaths:
        identity = _identity(contest, category, challenge_id)
        contest_paths = self.contest_paths(identity.contest_id)
        root = (
            contest_paths.challenges / identity.category / identity.challenge_id
        )
        self._assert_contained(root)
        context = root / "context"
        return ChallengePaths(
            root=root,
            state=root / "state.json",
            previous_state=root / "state.prev.json",
            events=root / "events.jsonl",
            lock=root / ".lock",
            runtime=root / "runtime",
            candidate_intents=root / "runtime" / "candidate-intents.json",
            context=context,
            current_context=context / "current.md",
            context_history=context / "history",
            runs=root / "runs",
            artifacts=root / "artifacts",
            knowledge=root / "knowledge",
            proof=root / "proof",
            exports=root / "exports",
        )

    # Short aliases make integrations read naturally.
    paths = challenge_paths

    def run_paths(
        self,
        contest: str | ChallengeIdentity | ChallengeState,
        category: str | None = None,
        challenge_id: str | None = None,
        run_id: str | None = None,
    ) -> RunPaths:
        if (
            isinstance(contest, (ChallengeIdentity, ChallengeState))
            and run_id is None
            and challenge_id is None
            and isinstance(category, str)
        ):
            run_id = category
            category = None
        identity = _identity(contest, category, challenge_id)
        if run_id is None:
            raise TypeError("run_id is required")
        run_id = _validate_component(run_id, "run_id")
        root = self.challenge_paths(identity).runs / run_id
        self._assert_contained(root)
        return RunPaths(
            root=root,
            request=root / "request.json",
            result=root / "result.json",
            validation=root / "validation.json",
            raw=root / "raw",
        )

    def _assert_contained(self, path: Path) -> None:
        try:
            path.resolve(strict=False).relative_to(
                self.workspace_root.resolve(strict=True)
            )
        except (FileNotFoundError, ValueError) as error:
            raise InvalidIdentity(
                f"state path escapes workspace: {path}"
            ) from error

    def initialize_contest(
        self,
        contest_id: str,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> ContestPaths:
        self.assert_mutations_allowed()
        paths = self.contest_paths(contest_id)
        paths.challenges.mkdir(parents=True, exist_ok=True)
        paths.runtime.mkdir(parents=True, exist_ok=True)
        if not paths.contest_json.exists():
            now = utc_now()
            atomic_write_json(
                paths.contest_json,
                {
                    "schema_version": CONTEST_MANIFEST_SCHEMA_VERSION,
                    "contest_id": contest_id,
                    "created_at": now,
                    "updated_at": now,
                    "metadata": dict(metadata or {}),
                },
            )
        if not paths.submissions.exists():
            atomic_write_text(paths.submissions, "")
        if not paths.board.exists():
            atomic_write_text(
                paths.board,
                render_board_markdown(contest_id, []),
                mode=0o644,
            )
        return paths

    create_contest = initialize_contest

    def create_challenge(
        self,
        contest: str | ChallengeIdentity,
        category: str | None = None,
        challenge_id: str | None = None,
        *,
        description: str = "",
        prompt: str = "",
        source_path: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        budget: Budget | Mapping[str, Any] | None = None,
        schema_version: int = CURRENT_SCHEMA_VERSION,
        exist_ok: bool = True,
    ) -> ChallengeState:
        self.assert_mutations_allowed()
        identity = _identity(contest, category, challenge_id)
        self.initialize_contest(identity.contest_id)
        paths = self.challenge_paths(identity)
        for directory in (
            paths.runtime,
            paths.context_history,
            paths.runs,
            paths.artifacts,
            paths.knowledge,
            paths.proof,
            paths.exports,
        ):
            directory.mkdir(parents=True, exist_ok=True)

        with ChallengeLock(paths.lock) as state_lock:
            state_lock.acquire()
            if paths.state.exists():
                if not exist_ok:
                    raise StateAlreadyExists(
                        f"challenge state already exists: {identity.key}"
                    )
                state = self._read_state(paths.state, expected=identity)
            else:
                if source_path is None:
                    source_path = (
                        Path("incoming")
                        / identity.contest_id
                        / identity.category
                        / identity.challenge_id
                    ).as_posix()
                state = new_challenge_state(
                    identity,
                    description=description,
                    prompt=prompt,
                    source_path=source_path,
                    metadata=metadata,
                    budget=budget,
                    schema_version=schema_version,
                )
                state.validate()
                payload = self._serialized_state(state)
                # Keeping an initial intact previous image makes recovery useful
                # even if the first later replacement is externally corrupted.
                atomic_write_bytes(paths.previous_state, payload)
                atomic_write_bytes(paths.state, payload)
                if not paths.events.exists():
                    atomic_write_text(paths.events, "")
                self._append_event_best_effort(
                    paths,
                    {
                        "event": "challenge_created",
                        "revision": state.revision,
                        "at": state.updated_at,
                    },
                )
            self._refresh_challenge_view_best_effort(state, paths)
        self._refresh_board_best_effort(identity.contest_id)
        return state

    initialize_challenge = create_challenge

    def load(
        self,
        contest: str | ChallengeIdentity | ChallengeState,
        category: str | None = None,
        challenge_id: str | None = None,
        *,
        recover: bool = True,
    ) -> ChallengeState:
        identity = _identity(contest, category, challenge_id)
        paths = self.challenge_paths(identity)
        try:
            return self._read_state(paths.state, expected=identity)
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            CorruptStateError,
        ) as current_error:
            if not recover:
                if isinstance(current_error, FileNotFoundError):
                    raise StateNotFound(
                        f"challenge state does not exist: {identity.key}"
                    ) from current_error
                raise CorruptStateError(
                    f"invalid state.json for {identity.key}: {current_error}"
                ) from current_error
            return self._recover(identity, current_error)

    load_state = load

    @staticmethod
    def candidate_intent_value_is_valid(value: object) -> bool:
        return candidate_value_is_valid(value)

    @staticmethod
    def _validate_candidate_intent_text(
        value: object,
        source: object,
        source_run_id: object,
    ) -> tuple[str, str, str | None]:
        if not StateStore.candidate_intent_value_is_valid(value):
            raise WorkerResultValidationError(
                "candidate intent value must be 1..1024 printable "
                "characters and at most 4096 UTF-8 bytes"
            )
        assert isinstance(value, str)
        if (
            not isinstance(source, str)
            or not source
            or len(source.encode("utf-8")) > _CANDIDATE_SOURCE_LIMIT_BYTES
        ):
            raise WorkerResultValidationError(
                "candidate intent source must be a non-empty string of at "
                "most 4096 UTF-8 bytes"
            )
        if source_run_id is not None and (
            not isinstance(source_run_id, str)
            or not source_run_id
            or len(source_run_id.encode("utf-8")) > 4096
        ):
            raise WorkerResultValidationError(
                "candidate intent source_run_id must be null or a non-empty "
                "string of at most 4096 UTF-8 bytes"
            )
        return value, source, source_run_id

    @staticmethod
    def _candidate_intent_lock(paths: ChallengePaths) -> FileLock:
        return FileLock(paths.runtime / "candidate-intents.lock")

    def _load_candidate_intents_locked(
        self,
        paths: ChallengePaths,
    ) -> list[dict[str, Any]]:
        try:
            descriptor = os.open(
                paths.candidate_intents,
                os.O_RDONLY
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except FileNotFoundError:
            return []
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise CorruptStateError(
                    "candidate intent journal is not a regular file"
                )
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                raise CorruptStateError(
                    "candidate intent journal mode must be 0600"
                )
            if metadata.st_size > _CANDIDATE_INTENT_FILE_LIMIT_BYTES:
                raise CorruptStateError(
                    "candidate intent journal exceeds its byte limit"
                )
            payload = bytearray()
            remaining = _CANDIDATE_INTENT_FILE_LIMIT_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                payload.extend(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
            if (
                len(payload) > _CANDIDATE_INTENT_FILE_LIMIT_BYTES
                or after.st_size != metadata.st_size
                or after.st_mtime_ns != metadata.st_mtime_ns
            ):
                raise CorruptStateError(
                    "candidate intent journal changed while being read"
                )
        finally:
            os.close(descriptor)
        try:
            raw = strict_json_loads(bytes(payload))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise CorruptStateError(
                f"cannot read candidate intent journal: {error}"
            ) from error
        if (
            not isinstance(raw, Mapping)
            or raw.get("schema_version")
            != CANDIDATE_INTENT_SCHEMA_VERSION
            or not isinstance(raw.get("intents"), list)
        ):
            raise CorruptStateError("invalid candidate intent journal")
        raw_intents = raw["intents"]
        if len(raw_intents) > _CANDIDATE_INTENT_LIMIT:
            raise CorruptStateError(
                "candidate intent journal exceeds its record limit"
            )
        intents: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        seen_values: set[str] = set()
        total_value_bytes = 0
        for index, raw_intent in enumerate(raw_intents):
            if not isinstance(raw_intent, Mapping):
                raise CorruptStateError(
                    f"invalid candidate intent at index {index}"
                )
            try:
                value, source, source_run_id = (
                    self._validate_candidate_intent_text(
                        raw_intent.get("value"),
                        raw_intent.get("source"),
                        raw_intent.get("source_run_id"),
                    )
                )
            except WorkerResultValidationError as error:
                raise CorruptStateError(
                    f"invalid candidate intent at index {index}: {error}"
                ) from error
            intent_id = raw_intent.get("id")
            observed_at = raw_intent.get("observed_at")
            tier_value = raw_intent.get(
                "tier", CandidateTier.GENERIC.value
            )
            format_epoch = raw_intent.get("format_epoch")
            try:
                tier = CandidateTier(str(tier_value))
            except ValueError as error:
                raise CorruptStateError(
                    f"invalid candidate intent tier at index {index}"
                ) from error
            expected_intent_id = "C-intent-" + hashlib.sha256(
                value.encode("utf-8")
            ).hexdigest()
            if (
                not isinstance(intent_id, str)
                or intent_id != expected_intent_id
                or not isinstance(observed_at, str)
                or not observed_at
                or len(observed_at.encode("utf-8")) > 128
                or intent_id in seen_ids
                or value in seen_values
                or (
                    format_epoch is not None
                    and (
                        isinstance(format_epoch, bool)
                        or not isinstance(format_epoch, int)
                        or format_epoch < 0
                    )
                )
            ):
                raise CorruptStateError(
                    f"invalid candidate intent fields at index {index}"
                )
            seen_ids.add(intent_id)
            seen_values.add(value)
            total_value_bytes += len(value.encode("utf-8"))
            intents.append(
                {
                    "id": intent_id,
                    "value": value,
                    "source": source,
                    "source_run_id": source_run_id,
                    "observed_at": observed_at,
                    "tier": tier.value,
                    "format_epoch": format_epoch,
                }
            )
        if total_value_bytes > _CANDIDATE_INTENT_VALUE_BYTES_LIMIT:
            raise CorruptStateError(
                "candidate intent journal exceeds its value byte limit"
            )
        return intents

    @staticmethod
    def _write_candidate_intents_locked(
        paths: ChallengePaths,
        intents: Sequence[Mapping[str, Any]],
    ) -> None:
        payload = {
            "schema_version": CANDIDATE_INTENT_SCHEMA_VERSION,
            "intents": [dict(intent) for intent in intents],
        }
        if (
            len(canonical_json_bytes(payload))
            > _CANDIDATE_INTENT_FILE_LIMIT_BYTES
        ):
            raise WorkerResultValidationError(
                "candidate intent journal exceeds its byte limit"
            )
        atomic_write_json(paths.candidate_intents, payload, mode=0o600)

    def record_candidate_intent(
        self,
        identity: ChallengeIdentity,
        *,
        value: str,
        source: str,
        source_run_id: str | None = None,
        observed_at: str | None = None,
        tier: CandidateTier = CandidateTier.GENERIC,
        format_epoch: int | None = None,
    ) -> str:
        """Durably stage one bounded candidate before terminal notification."""

        self.assert_mutations_allowed()
        identity = _identity(identity)
        value, source, source_run_id = self._validate_candidate_intent_text(
            value,
            source,
            source_run_id,
        )
        actual_observed_at = observed_at or utc_now()
        if not isinstance(tier, CandidateTier):
            raise WorkerResultValidationError(
                "candidate intent tier must be a CandidateTier"
            )
        if format_epoch is not None and (
            isinstance(format_epoch, bool)
            or not isinstance(format_epoch, int)
            or format_epoch < 0
        ):
            raise WorkerResultValidationError(
                "candidate intent format_epoch must be a non-negative integer"
            )
        if (
            not isinstance(actual_observed_at, str)
            or not actual_observed_at
            or len(actual_observed_at.encode("utf-8")) > 128
        ):
            raise WorkerResultValidationError(
                "candidate intent observed_at must be a non-empty string of "
                "at most 128 UTF-8 bytes"
            )
        intent_id = "C-intent-" + hashlib.sha256(
            value.encode("utf-8")
        ).hexdigest()
        record = {
            "id": intent_id,
            "value": value,
            "source": source,
            "source_run_id": source_run_id,
            "observed_at": actual_observed_at,
            "tier": tier.value,
            "format_epoch": format_epoch,
        }
        paths = self.challenge_paths(identity)
        with self._candidate_intent_lock(paths) as intent_lock:
            intent_lock.acquire()
            intents = self._load_candidate_intents_locked(paths)
            existing = next(
                (intent for intent in intents if intent["value"] == value),
                None,
            )
            if existing is not None:
                return str(existing["id"])
            if len(intents) >= _CANDIDATE_INTENT_LIMIT:
                raise WorkerResultValidationError(
                    "candidate intent journal is full"
                )
            if (
                sum(
                    len(str(intent["value"]).encode("utf-8"))
                    for intent in intents
                )
                + len(value.encode("utf-8"))
                > _CANDIDATE_INTENT_VALUE_BYTES_LIMIT
            ):
                raise WorkerResultValidationError(
                    "candidate intent journal value byte limit is exhausted"
                )
            self._write_candidate_intents_locked(paths, (*intents, record))
        return intent_id

    def load_candidate_intents(
        self,
        identity: ChallengeIdentity,
    ) -> tuple[dict[str, Any], ...]:
        """Read the bounded recovery journal without changing canonical state."""

        paths = self.challenge_paths(identity)
        with self._candidate_intent_lock(paths) as intent_lock:
            intent_lock.acquire()
            return tuple(
                dict(intent)
                for intent in self._load_candidate_intents_locked(paths)
            )

    def clear_candidate_intents(
        self,
        identity: ChallengeIdentity,
        values: Sequence[str],
    ) -> None:
        """Clear intents only after their values are canonical candidates."""

        cleared = frozenset(values)
        if not cleared:
            return
        self.assert_mutations_allowed()
        paths = self.challenge_paths(identity)
        with self._candidate_intent_lock(paths) as intent_lock:
            intent_lock.acquire()
            intents = self._load_candidate_intents_locked(paths)
            canonical_values = {
                candidate.value
                for candidate in self._read_state(
                    paths.state,
                    expected=_identity(identity),
                ).candidates
            }
            missing = cleared - canonical_values
            if missing:
                raise WorkerResultValidationError(
                    "cannot clear candidate intents before canonical commit"
                )
            remaining = [
                intent
                for intent in intents
                if intent["value"] not in cleared
            ]
            if len(remaining) != len(intents):
                self._write_candidate_intents_locked(paths, remaining)

    def reconcile_candidate_intents(
        self,
        identity: ChallengeIdentity,
    ) -> ChallengeState:
        """Commit crash-left candidates at a session boundary without printing."""

        self.assert_mutations_allowed()
        identity = _identity(identity)
        paths = self.challenge_paths(identity)
        with self._candidate_intent_lock(paths) as intent_lock:
            intent_lock.acquire()
            intents = self._load_candidate_intents_locked(paths)
            current = self._read_state(paths.state, expected=identity)
            if not intents:
                return current
            existing_values = {
                candidate.value for candidate in current.candidates
            }
            additions = [
                intent
                for intent in intents
                if intent["value"] not in existing_values
            ]
            if additions:

                def apply(state: ChallengeState) -> None:
                    known_values = {
                        candidate.value for candidate in state.candidates
                    }
                    run_ids = {run.id for run in state.runs}
                    candidate_ids = {
                        candidate.id for candidate in state.candidates
                    }
                    for intent in additions:
                        value = str(intent["value"])
                        if value in known_values:
                            continue
                        candidate_id = str(intent["id"])
                        if candidate_id in candidate_ids:
                            raise CorruptStateError(
                                "candidate intent id conflicts with canonical "
                                "state"
                            )
                        intended_run = intent.get("source_run_id")
                        source_run_id = (
                            str(intended_run)
                            if intended_run in run_ids
                            else None
                        )
                        state.candidates.append(
                            FlagCandidate(
                                id=candidate_id,
                                value=value,
                                status=(
                                    CandidateStatus.OBSERVED_CANDIDATE
                                ),
                                source_run_id=source_run_id,
                                locator=str(intent["source"]),
                                created_at=str(intent["observed_at"]),
                                tier=CandidateTier(
                                    str(
                                        intent.get(
                                            "tier",
                                            CandidateTier.GENERIC.value,
                                        )
                                    )
                                ),
                                format_epoch=(
                                    int(intent["format_epoch"])
                                    if intent.get("format_epoch") is not None
                                    else None
                                ),
                                extra={
                                    "recovered_from_candidate_intent": True,
                                    **(
                                        {
                                            "intended_source_run_id": (
                                                intended_run
                                            )
                                        }
                                        if intended_run is not None
                                        and source_run_id is None
                                        else {}
                                    ),
                                },
                            )
                        )
                        known_values.add(value)
                        candidate_ids.add(candidate_id)

                committed = self.update(
                    identity,
                    apply,
                    expected_revision=current.revision,
                )
            else:
                committed = current
            # Every intent is now represented in canonical state. If this
            # atomic clear is interrupted, value deduplication makes a later
            # reconciliation idempotent.
            self._write_candidate_intents_locked(paths, [])
            return committed

    def _read_state(
        self,
        path: Path,
        *,
        expected: ChallengeIdentity | None = None,
    ) -> ChallengeState:
        payload = _read_bounded_regular(
            path,
            maximum_bytes=MAX_CANONICAL_STATE_BYTES,
        )
        return self._decode_state(payload, path, expected=expected)

    @staticmethod
    def _read_recovery_journal(
        path: Path,
        *,
        maximum_bytes: int,
    ) -> bytes:
        try:
            return _read_bounded_regular(
                path,
                maximum_bytes=maximum_bytes,
            )
        except FileNotFoundError:
            return b""
        except (OSError, CorruptStateError) as error:
            raise CorruptStateError(
                f"cannot read recovery journal {path}: {error}"
            ) from error

    @staticmethod
    def _decode_submission_ledger_snapshot(
        payload: bytes,
        path: Path,
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for index, raw_line in enumerate(payload.split(b"\n"), start=1):
            if not raw_line.strip():
                continue
            try:
                record = strict_json_loads(raw_line)
            except (UnicodeError, ValueError) as error:
                raise CorruptStateError(
                    f"invalid recovery ledger line {index} in {path}: "
                    f"{error}"
                ) from error
            if not isinstance(record, dict):
                raise CorruptStateError(
                    f"recovery ledger line {index} in {path} is not an "
                    "object"
                )
            records.append(record)
        return records

    def _recovery_submission_snapshots(
        self,
        identity: ChallengeIdentity,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Read stable contest journals without reversing the store lock order."""

        contest_paths = self.contest_paths(identity.contest_id)

        def read_pair() -> tuple[bytes, bytes]:
            return (
                self._read_recovery_journal(
                    contest_paths.submissions,
                    maximum_bytes=(
                        _SUBMISSION_LEDGER_RECOVERY_LIMIT_BYTES
                    ),
                ),
                self._read_recovery_journal(
                    contest_paths.submission_intents,
                    maximum_bytes=(
                        _SUBMISSION_INTENT_RECOVERY_LIMIT_BYTES
                    ),
                ),
            )

        ledger_payload, intent_payload = read_pair()
        records = self._decode_submission_ledger_snapshot(
            ledger_payload,
            contest_paths.submissions,
        )
        self._ledger_records_by_id(records)
        if intent_payload:
            try:
                raw_intents = strict_json_loads(intent_payload)
            except (UnicodeError, ValueError) as error:
                raise CorruptStateError(
                    "cannot decode submission intent recovery snapshot: "
                    f"{error}"
                ) from error
            intents = self._decode_submission_intents(
                contest_paths,
                raw_intents,
            )
        else:
            intents = []

        # A descriptor is stable while read, but atomic journal replacement can
        # race between the two descriptors. Require an identical second
        # snapshot before authorizing rollback of canonical challenge state.
        if read_pair() != (ledger_payload, intent_payload):
            raise CorruptStateError(
                "submission journals changed during state recovery"
            )
        return records, intents

    def _require_recovery_submission_consistency(
        self,
        identity: ChallengeIdentity,
        recovered: ChallengeState,
    ) -> None:
        records, intents = self._recovery_submission_snapshots(identity)
        submissions = {
            submission.id: submission
            for submission in recovered.submissions
        }
        candidates = {
            candidate.id: candidate for candidate in recovered.candidates
        }
        relevant = [
            record
            for record in (*records, *intents)
            if record.get("contest_id") == identity.contest_id
            and record.get("category") == identity.category
            and record.get("challenge_id") == identity.challenge_id
        ]
        for record in relevant:
            revision = record.get("state_revision")
            if (
                isinstance(revision, bool)
                or not isinstance(revision, int)
                or revision < 0
            ):
                raise CorruptStateError(
                    "submission recovery record has an invalid state_revision"
                )
            submission_id = record.get("id")
            candidate_id = record.get("candidate_id")
            status = record.get("status")
            if revision > recovered.revision:
                raise CorruptStateError(
                    f"submission {submission_id!r} at revision {revision} "
                    f"is newer than recoverable state revision "
                    f"{recovered.revision}"
                )
            submission = (
                submissions.get(submission_id)
                if isinstance(submission_id, str)
                else None
            )
            candidate = (
                candidates.get(candidate_id)
                if isinstance(candidate_id, str)
                else None
            )
            if (
                submission is None
                or candidate is None
                or submission.candidate_id != candidate_id
                or submission.status.value != status
                or candidate.value != record.get("flag")
                or submission.submitted_at != record.get("recorded_at")
                or submission.response != record.get("response")
                or submission.proof_passed
                != record.get("proof_passed")
                or submission.format_ok != record.get("format_ok")
                or submission.points != record.get("points")
                or (
                    submission.override.to_dict()
                    if submission.override is not None
                    else None
                )
                != record.get("override")
            ):
                raise CorruptStateError(
                    f"submission {submission_id!r} is missing from or "
                    "conflicts with the recoverable challenge state"
                )

    def _recover(
        self,
        identity: ChallengeIdentity,
        original_error: BaseException,
    ) -> ChallengeState:
        paths = self.challenge_paths(identity)
        with ChallengeLock(paths.lock) as state_lock:
            state_lock.acquire()
            # Another writer may have repaired the state while we waited.
            try:
                return self._read_state(paths.state, expected=identity)
            except (
                OSError,
                ValueError,
                KeyError,
                TypeError,
                CorruptStateError,
            ):
                pass
            try:
                recovered = self._read_state(
                    paths.previous_state, expected=identity
                )
                recovered_payload = self._serialized_state(recovered)
            except (
                OSError,
                ValueError,
                KeyError,
                TypeError,
                CorruptStateError,
            ) as previous_error:
                if isinstance(
                    original_error, FileNotFoundError
                ) and isinstance(previous_error, FileNotFoundError):
                    raise StateNotFound(
                        f"challenge state does not exist: {identity.key}"
                    ) from previous_error
                raise CorruptStateError(
                    f"state.json and state.prev.json are unusable for "
                    f"{identity.key}: current={original_error}; "
                    f"previous={previous_error}"
                ) from previous_error
            self._require_recovery_submission_consistency(
                identity,
                recovered,
            )
            atomic_write_bytes(paths.state, recovered_payload)
            self._append_event_best_effort(
                paths,
                {
                    "event": "state_recovered",
                    "revision": recovered.revision,
                    "at": utc_now(),
                    "reason": str(original_error),
                },
            )
            self._refresh_challenge_view_best_effort(recovered, paths)
        self._refresh_board_best_effort(identity.contest_id)
        return recovered

    def save(
        self,
        state: ChallengeState,
        *,
        expected_revision: int | None = None,
        validate_artifacts: bool = True,
    ) -> ChallengeState:
        self.assert_mutations_allowed()
        state.validate()
        identity = _identity(state)
        paths = self.challenge_paths(identity)
        with ChallengeLock(paths.lock) as state_lock:
            lock_started = time.monotonic()
            state_lock.acquire()
            lock_wait_ms = (time.monotonic() - lock_started) * 1000
            current = self._read_state(paths.state, expected=identity)
            expected = (
                state.revision
                if expected_revision is None
                else expected_revision
            )
            if current.revision != expected:
                raise RevisionConflict(expected, current.revision)
            proposed = ChallengeState.from_dict(state.to_dict())
            return self._commit_locked(
                paths,
                current,
                proposed,
                validate_artifacts=validate_artifacts,
                lock_wait_ms=lock_wait_ms,
            )

    save_state = save

    def update(
        self,
        contest: str | ChallengeIdentity | ChallengeState,
        category: str | Callable[[ChallengeState], _T | None] | None = None,
        challenge_id: str | None = None,
        mutator: Callable[[ChallengeState], _T | None] | None = None,
        *,
        expected_revision: int | None = None,
        validate_artifacts: bool = True,
    ) -> ChallengeState:
        """Atomically load, mutate, validate, and replace a challenge state.

        ``update(identity, mutator)`` and
        ``update(contest, category, challenge, mutator)`` are both accepted.
        The mutator may edit its argument and return ``None`` or return a
        replacement :class:`ChallengeState`.
        """

        if isinstance(contest, (ChallengeIdentity, ChallengeState)) and callable(
            category
        ):
            mutator = category
            category = None
        if mutator is None:
            raise TypeError("a state mutator is required")
        self.assert_mutations_allowed()
        identity = _identity(
            contest,
            category if isinstance(category, str) else None,
            challenge_id,
        )
        paths = self.challenge_paths(identity)
        with ChallengeLock(paths.lock) as state_lock:
            lock_started = time.monotonic()
            state_lock.acquire()
            lock_wait_ms = (time.monotonic() - lock_started) * 1000
            current = self._read_state(paths.state, expected=identity)
            if (
                expected_revision is not None
                and current.revision != expected_revision
            ):
                raise RevisionConflict(expected_revision, current.revision)
            working = ChallengeState.from_dict(current.to_dict())
            returned = mutator(working)
            if isinstance(returned, ChallengeState):
                proposed = returned
            elif returned is None:
                proposed = working
            else:
                raise TypeError(
                    "state mutator must return ChallengeState or None"
                )
            if proposed.identity != identity:
                raise InvalidIdentity(
                    "a state update cannot change challenge identity"
                )
            return self._commit_locked(
                paths,
                current,
                proposed,
                validate_artifacts=validate_artifacts,
                lock_wait_ms=lock_wait_ms,
            )

    mutate = update

    def _commit_locked(
        self,
        paths: ChallengePaths,
        current: ChallengeState,
        proposed: ChallengeState,
        *,
        validate_artifacts: bool,
        lock_wait_ms: float = 0.0,
    ) -> ChallengeState:
        commit_started = time.monotonic()
        if proposed.identity != current.identity:
            raise InvalidIdentity("state identity cannot change during commit")
        # Stop oversized in-memory collections before cloning/serializing them.
        proposed.validate()
        committed = ChallengeState.from_dict(proposed.to_dict())
        # Ordinary writers preserve the source state protocol.  Only the
        # explicit migration transaction may change it.
        committed.schema_version = current.schema_version
        committed.revision = current.revision + 1
        committed.created_at = current.created_at
        committed.updated_at = utc_now()
        committed.validate()
        serialization_started = time.monotonic()
        total_artifact_bytes = 0
        current_artifacts = {
            (
                artifact.id,
                artifact.path,
                artifact.sha256,
                artifact.size,
            )
            for artifact in current.artifacts
        }
        delta_artifact_count = 0
        for artifact in committed.artifacts:
            if (
                artifact.id,
                artifact.path,
                artifact.sha256,
                artifact.size,
            ) not in current_artifacts:
                delta_artifact_count += 1
            if validate_artifacts:
                artifact_path = validate_artifact(paths.root, artifact)
            else:
                artifact_path = _resolve_artifact_path(
                    paths.root,
                    artifact,
                )
                actual_size = artifact_path.stat().st_size
                if (
                    artifact.size is not None
                    and actual_size != artifact.size
                ):
                    raise ArtifactValidationError(
                        f"artifact {artifact.id!r} size mismatch: expected "
                        f"{artifact.size}, got {actual_size}"
                    )
            total_artifact_bytes += artifact_path.stat().st_size
            if total_artifact_bytes > self.max_artifact_bytes:
                raise ArtifactValidationError(
                    "canonical artifact bytes exceed configured limit "
                    f"{self.max_artifact_bytes}"
                )
        committed_payload = self._serialized_state(committed)
        serialization_ms = (
            time.monotonic() - serialization_started
        ) * 1000

        # Preserve the exact last readable canonical bytes before replacement.
        previous_payload = _read_bounded_regular(
            paths.state,
            maximum_bytes=MAX_CANONICAL_STATE_BYTES,
        )
        # Reparse once before trusting externally altered bytes as recovery state.
        self._decode_state(
            previous_payload,
            paths.state,
            expected=current.identity,
        )
        fsync_started = time.monotonic()
        atomic_write_bytes(paths.previous_state, previous_payload)
        atomic_write_bytes(paths.state, committed_payload)
        fsync_ms = (time.monotonic() - fsync_started) * 1000

        self._append_event_best_effort(
            paths,
            {
                "event": "state_updated",
                "from_revision": current.revision,
                "revision": committed.revision,
                "at": committed.updated_at,
            },
        )
        self._refresh_challenge_view_best_effort(committed, paths)
        board_started = time.monotonic()
        self._refresh_board_best_effort(committed.contest_id)
        board_ms = (time.monotonic() - board_started) * 1000
        self._append_telemetry_best_effort(
            {
                "event": "state_commit",
                "contest_id": committed.contest_id,
                "category": committed.category,
                "challenge_id": committed.challenge_id,
                "revision": committed.revision,
                "commit_ms": round(
                    (time.monotonic() - commit_started) * 1000,
                    3,
                ),
                "lock_wait_ms": round(lock_wait_ms, 3),
                "serialization_ms": round(serialization_ms, 3),
                "fsync_ms": round(fsync_ms, 3),
                "board_scan_ms": round(board_ms, 3),
                "artifact_hash_bytes": total_artifact_bytes,
                "full_artifact_count": len(committed.artifacts),
                "delta_shadow_artifact_count": delta_artifact_count,
                "delta_shadow_mismatches": 0,
                "board_shadow_match": self._board_projection_matches(
                    committed
                ),
            }
        )
        return committed

    def verify_artifacts(
        self,
        contest: str | ChallengeIdentity | ChallengeState,
        category: str | None = None,
        challenge_id: str | None = None,
    ) -> dict[str, Path]:
        identity = _identity(contest, category, challenge_id)
        paths = self.challenge_paths(identity)
        state = self.load(identity)
        return {
            artifact.id: validate_artifact(paths.root, artifact)
            for artifact in state.artifacts
        }

    def assert_revision(
        self,
        contest: str | ChallengeIdentity | ChallengeState,
        category: str | int | None = None,
        challenge_id: str | None = None,
        expected_revision: int | None = None,
    ) -> ChallengeState:
        """Load state and reject a stale revision.

        Both ``assert_revision(identity, revision)`` and the four-argument form
        are supported.
        """

        if isinstance(contest, (ChallengeIdentity, ChallengeState)) and isinstance(
            category, int
        ):
            expected_revision = category
            category = None
        if expected_revision is None:
            raise TypeError("expected_revision is required")
        state = self.load(
            contest,
            category if isinstance(category, str) else None,
            challenge_id,
        )
        if state.revision != expected_revision:
            raise RevisionConflict(expected_revision, state.revision)
        return state

    def create_run(
        self,
        contest: str | ChallengeIdentity | ChallengeState,
        category: str | None = None,
        challenge_id: str | None = None,
        run_id: str | None = None,
        *,
        request: Mapping[str, Any] | None = None,
        base_revision: int | None = None,
    ) -> RunPaths:
        self.assert_mutations_allowed()
        if (
            isinstance(contest, (ChallengeIdentity, ChallengeState))
            and run_id is None
            and challenge_id is None
            and isinstance(category, str)
        ):
            run_id = category
            category = None
        identity = _identity(contest, category, challenge_id)
        if run_id is None:
            run_id = (
                utc_now()
                .replace("-", "")
                .replace(":", "")
                .replace("T", "-")
                .replace("Z", "")
                + "-"
                + uuid.uuid4().hex[:8]
            )
        run_id = _validate_component(run_id, "run_id")
        state = self.load(identity)
        base = state.revision if base_revision is None else base_revision
        if base != state.revision:
            raise RevisionConflict(base, state.revision)
        paths = self.run_paths(identity, run_id=run_id)
        try:
            paths.root.mkdir(parents=True, exist_ok=False)
        except FileExistsError as error:
            raise StateAlreadyExists(
                f"run already exists: {identity.key}/{run_id}"
            ) from error
        paths.raw.mkdir()
        payload = dict(request or {})
        payload.update(
            {
                "schema_version": RUN_ENVELOPE_SCHEMA_VERSION,
                "contest_id": identity.contest_id,
                "category": identity.category,
                "challenge_id": identity.challenge_id,
                "run_id": run_id,
                "base_revision": base,
                "created_at": payload.get("created_at", utc_now()),
            }
        )
        atomic_write_json(paths.request, payload)
        return paths

    def write_run_result(
        self,
        contest: str | ChallengeIdentity | ChallengeState,
        category: str | None = None,
        challenge_id: str | Mapping[str, Any] | None = None,
        run_id: str | None = None,
        result: Mapping[str, Any] | None = None,
    ) -> Path:
        self.assert_mutations_allowed()
        if isinstance(contest, (ChallengeIdentity, ChallengeState)):
            if isinstance(challenge_id, Mapping) and result is None:
                result = challenge_id
                challenge_id = None
                run_id = category
                category = None
            elif run_id is None and challenge_id is None and category is not None:
                run_id = category
                category = None
        if run_id is None or result is None:
            raise TypeError("run_id and result are required")
        identity = _identity(
            contest,
            category,
            challenge_id if isinstance(challenge_id, str) else None,
        )
        paths = self.run_paths(identity, run_id=run_id)
        if not paths.root.is_dir():
            raise StateNotFound(f"run does not exist: {identity.key}/{run_id}")
        payload = dict(result)
        payload.setdefault("schema_version", WORKER_RESULT_SCHEMA_VERSION)
        payload.setdefault("contest_id", identity.contest_id)
        payload.setdefault("category", identity.category)
        payload.setdefault("challenge_id", identity.challenge_id)
        payload.setdefault("run_id", run_id)
        atomic_write_json(paths.result, payload)
        return paths.result

    def write_run_validation(
        self,
        contest: str | ChallengeIdentity | ChallengeState,
        category: str | None = None,
        challenge_id: str | Mapping[str, Any] | None = None,
        run_id: str | None = None,
        validation: Mapping[str, Any] | None = None,
    ) -> Path:
        self.assert_mutations_allowed()
        if isinstance(contest, (ChallengeIdentity, ChallengeState)):
            if isinstance(challenge_id, Mapping) and validation is None:
                validation = challenge_id
                challenge_id = None
                run_id = category
                category = None
            elif run_id is None and challenge_id is None and category is not None:
                run_id = category
                category = None
        if run_id is None or validation is None:
            raise TypeError("run_id and validation are required")
        identity = _identity(
            contest,
            category,
            challenge_id if isinstance(challenge_id, str) else None,
        )
        paths = self.run_paths(identity, run_id=run_id)
        if not paths.root.is_dir():
            raise StateNotFound(f"run does not exist: {identity.key}/{run_id}")
        payload = dict(validation)
        payload.setdefault("run_id", run_id)
        payload.setdefault("validated_at", utc_now())
        atomic_write_json(paths.validation, payload)
        return paths.validation

    def validate_worker_result(
        self,
        contest: str | ChallengeIdentity | ChallengeState,
        category: str | None = None,
        challenge_id: str | None = None,
        run_id: str | None = None,
        result: Mapping[str, Any] | None = None,
        *,
        persist_validation: bool = True,
        expected_base_revision: int | None = None,
    ) -> list[ArtifactReference]:
        """Validate identity, base revision, and artifacts in a worker result."""

        if (
            isinstance(contest, (ChallengeIdentity, ChallengeState))
            and run_id is None
            and challenge_id is None
            and isinstance(category, str)
        ):
            run_id = category
            category = None
        identity = _identity(contest, category, challenge_id)
        if run_id is None:
            raise TypeError("run_id is required")
        run_paths = self.run_paths(identity, run_id=run_id)
        try:
            if result is None:
                loaded = read_json(run_paths.result)
                if not isinstance(loaded, Mapping):
                    raise WorkerResultValidationError(
                        "worker result root must be an object"
                    )
                result = loaded
            request = read_json(run_paths.request)
            if not isinstance(request, Mapping):
                raise WorkerResultValidationError(
                    "run request root must be an object"
                )
            self._validate_result_identity(identity, run_id, result)
            base_revision = result.get(
                "base_revision",
                result.get(
                    "read_revision",
                    request.get("base_revision"),
                ),
            )
            if base_revision is None:
                raise WorkerResultValidationError(
                    "worker result has no base_revision"
                )
            normalized_base_revision = int(base_revision)
            if expected_base_revision is None:
                self.assert_revision(identity, normalized_base_revision)
            elif normalized_base_revision != expected_base_revision:
                raise WorkerResultValidationError(
                    "worker result base revision does not match its reserved "
                    f"snapshot: {normalized_base_revision} != "
                    f"{expected_base_revision}"
                )
            records = result.get("artifacts", [])
            if records is None:
                records = []
            if not isinstance(records, list) or not all(
                isinstance(record, Mapping) for record in records
            ):
                raise WorkerResultValidationError(
                    "worker result artifacts must be an array of objects"
                )
            artifacts = [
                ArtifactReference.from_dict(record) for record in records
            ]
            challenge_paths = self.challenge_paths(identity)
            for artifact in artifacts:
                if (
                    artifact.source_run_id is not None
                    and artifact.source_run_id != run_id
                ):
                    raise WorkerResultValidationError(
                        f"artifact {artifact.id!r} names another source run"
                    )
                artifact.source_run_id = run_id
                validate_artifact(challenge_paths.root, artifact)
            if persist_validation:
                self.write_run_validation(
                    identity,
                    run_id,
                    {
                        "ok": True,
                        "base_revision": normalized_base_revision,
                        "artifact_ids": [
                            artifact.id for artifact in artifacts
                        ],
                        "errors": [],
                    },
                )
            return artifacts
        except Exception as error:
            if persist_validation and run_paths.root.is_dir():
                try:
                    self.write_run_validation(
                        identity,
                        run_id,
                        {
                            "ok": False,
                            "errors": [str(error)],
                            "error_type": type(error).__name__,
                        },
                    )
                except OSError:
                    pass
            raise

    validate_result = validate_worker_result

    def _validate_result_identity(
        self,
        identity: ChallengeIdentity,
        run_id: str,
        result: Mapping[str, Any],
    ) -> None:
        expected = {
            "contest_id": identity.contest_id,
            "category": identity.category,
            "challenge_id": identity.challenge_id,
            "run_id": run_id,
        }
        for field, value in expected.items():
            if field in result and str(result[field]) != value:
                raise WorkerResultValidationError(
                    f"worker result {field}={result[field]!r}, expected "
                    f"{value!r}"
                )
        if (
            "schema_version" in result
            and int(result["schema_version"]) != WORKER_RESULT_SCHEMA_VERSION
        ):
            raise WorkerResultValidationError(
                f"worker result schema_version={result['schema_version']}, "
                f"expected {WORKER_RESULT_SCHEMA_VERSION}"
            )

    def refresh_views(
        self,
        contest: str | ChallengeIdentity | ChallengeState,
        category: str | None = None,
        challenge_id: str | None = None,
    ) -> dict[str, Any]:
        identity = _identity(contest, category, challenge_id)
        state = self.load(identity)
        paths = self.challenge_paths(identity)
        atomic_write_text(
            paths.current_context,
            render_current_markdown(state),
            mode=0o644,
        )
        self.refresh_board(identity.contest_id)
        return board_entry(state)

    def refresh_board(
        self,
        contest_id: str,
        *,
        reconcile_submissions: bool = True,
    ) -> list[dict[str, Any]]:
        contest = self.initialize_contest(contest_id)
        if reconcile_submissions:
            self.reconcile_submissions(contest_id)
        lock = FileLock(contest.runtime / "board.lock")
        active_error: BaseException | None = None
        try:
            # Install this caller-side cleanup guard before acquire().  If an
            # interrupt lands after FileLock has acquired the flock but before
            # the call returns, the finally below still releases that exact
            # descriptor.
            lock.acquire()
            entries: list[dict[str, Any]] = []
            if contest.challenges.exists():
                for state_path in sorted(
                    contest.challenges.glob("*/*/state.json")
                ):
                    try:
                        state = self._read_state(state_path)
                    except (
                        OSError,
                        ValueError,
                        KeyError,
                        TypeError,
                        CorruptStateError,
                    ):
                        continue
                    if state.contest_id == contest_id:
                        entries.append(board_entry(state))
            atomic_write_text(
                contest.board,
                render_board_markdown(contest_id, entries),
                mode=0o644,
            )
            atomic_write_json(
                contest.root / "board.json",
                {
                    "schema_version": BOARD_VIEW_SCHEMA_VERSION,
                    "contest_id": contest_id,
                    "updated_at": utc_now(),
                    "challenges": entries,
                },
                mode=0o644,
            )
            return entries
        except BaseException as error:
            active_error = error
            raise
        finally:
            try:
                lock.release()
            except BaseException as release_error:
                if (
                    active_error is not None
                    and not isinstance(active_error, Exception)
                ):
                    active_error.add_note(
                        "board refresh lock release failed: "
                        f"{release_error}"
                    )
                else:
                    raise

    def _refresh_challenge_view_best_effort(
        self, state: ChallengeState, paths: ChallengePaths
    ) -> None:
        try:
            atomic_write_text(
                paths.current_context,
                render_current_markdown(state),
                mode=0o644,
            )
        except Exception as error:  # noqa: BLE001 - derived view is best effort
            self.last_view_errors.append(str(error))

    def _refresh_board_best_effort(self, contest_id: str) -> None:
        try:
            # State commits may already hold submissions.lock. Avoid taking that
            # lock recursively from the derived-view refresh path; explicit
            # status/board reads perform reconciliation before rendering.
            self.refresh_board(contest_id, reconcile_submissions=False)
        except Exception as error:  # noqa: BLE001 - derived view is best effort
            self.last_view_errors.append(str(error))

    def _board_projection_matches(self, state: ChallengeState) -> bool:
        """Compare the full board render with one challenge-local projection."""

        try:
            board = read_json(
                self.contest_paths(state.contest_id).root / "board.json"
            )
            if not isinstance(board, Mapping):
                return False
            entries = board.get("challenges")
            if not isinstance(entries, list):
                return False
            actual = next(
                (
                    entry
                    for entry in entries
                    if isinstance(entry, Mapping)
                    and entry.get("category") == state.category
                    and entry.get("challenge_id") == state.challenge_id
                ),
                None,
            )
            return actual == board_entry(state)
        except (OSError, ValueError, TypeError):
            return False

    def _append_telemetry_best_effort(
        self,
        event: Mapping[str, Any],
    ) -> None:
        """Append bounded operational timings without prompts or output data."""

        try:
            append_json_line(
                self.root / "runtime" / "telemetry.jsonl",
                {
                    "schema_version": 1,
                    "at": utc_now(),
                    **dict(event),
                },
            )
        except Exception as error:  # noqa: BLE001 - shadow data is best effort
            self.last_view_errors.append(str(error))

    def _append_event_best_effort(
        self, paths: ChallengePaths, event: Mapping[str, Any]
    ) -> None:
        try:
            payload = {
                "schema_version": EVENT_RECORD_SCHEMA_VERSION,
                "contest_id": paths.root.parents[2].name,
                "category": paths.root.parent.name,
                "challenge_id": paths.root.name,
                **dict(event),
            }
            append_json_line(paths.events, payload)
        except Exception as error:  # noqa: BLE001 - event log is best effort
            self.last_view_errors.append(str(error))

    def board_entry(
        self,
        contest: str | ChallengeIdentity | ChallengeState,
        category: str | None = None,
        challenge_id: str | None = None,
    ) -> dict[str, Any]:
        return board_entry(self.load(contest, category, challenge_id))

    @staticmethod
    def _submission_intent_sort_key(
        record: Mapping[str, Any],
    ) -> tuple[str, str, str, str]:
        return (
            str(record.get("recorded_at", "")),
            str(record.get("category", "")),
            str(record.get("challenge_id", "")),
            str(record.get("id", "")),
        )

    @staticmethod
    def _submission_record_signature(
        record: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            name: record.get(name)
            for name in (
                "id",
                "recorded_at",
                "contest_id",
                "category",
                "challenge_id",
                "candidate_id",
                "flag",
                "status",
                "response",
                "proof_passed",
                "format_ok",
                "points",
                "override",
                "state_revision",
            )
        }

    def _load_submission_intents(
        self,
        paths: ContestPaths,
    ) -> list[dict[str, Any]]:
        try:
            raw = read_json(paths.submission_intents)
        except FileNotFoundError:
            return []
        except (OSError, ValueError, TypeError) as error:
            raise CorruptStateError(
                f"cannot read submission intent journal: {error}"
            ) from error
        return self._decode_submission_intents(paths, raw)

    def _decode_submission_intents(
        self,
        paths: ContestPaths,
        raw: Any,
    ) -> list[dict[str, Any]]:
        if not isinstance(raw, Mapping):
            raise CorruptStateError(
                "submission intent journal root must be an object"
            )
        if (
            raw.get("schema_version") != SUBMISSION_INTENT_SCHEMA_VERSION
            or raw.get("contest_id") != paths.root.name
            or not isinstance(raw.get("intents"), list)
        ):
            raise CorruptStateError("invalid submission intent journal")

        intents: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        required = {
            "schema_version",
            "id",
            "recorded_at",
            "contest_id",
            "category",
            "challenge_id",
            "candidate_id",
            "flag",
            "status",
            "response",
            "proof_passed",
            "format_ok",
            "points",
            "state_revision",
        }
        for index, value in enumerate(raw["intents"]):
            if not isinstance(value, Mapping) or not required <= set(value):
                raise CorruptStateError(
                    f"invalid submission intent at index {index}"
                )
            record = dict(value)
            try:
                identity = _identity(
                    str(record["contest_id"]),
                    str(record["category"]),
                    str(record["challenge_id"]),
                )
                status = SubmissionStatus(str(record["status"]))
            except (StateStoreError, ValueError) as error:
                raise CorruptStateError(
                    f"invalid submission intent identity/status at index {index}"
                ) from error
            submission_id = record["id"]
            if (
                identity.contest_id != paths.root.name
                or not isinstance(submission_id, str)
                or not submission_id
                or submission_id in seen_ids
                or not isinstance(record["recorded_at"], str)
                or not record["recorded_at"]
                or not isinstance(record["candidate_id"], str)
                or not record["candidate_id"]
                or not isinstance(record["flag"], str)
                or not record["flag"]
                or not isinstance(record["proof_passed"], bool)
                or not isinstance(record["format_ok"], bool)
                or (
                    record["response"] is not None
                    and not isinstance(record["response"], str)
                )
                or (
                    record["points"] is not None
                    and (
                        isinstance(record["points"], bool)
                        or not isinstance(record["points"], (int, float))
                    )
                )
                or (
                    record.get("override") is not None
                    and not isinstance(record.get("override"), Mapping)
                )
                or isinstance(record["state_revision"], bool)
                or not isinstance(record["state_revision"], int)
                or record["state_revision"] < 0
                or status
                not in {
                    SubmissionStatus.ACCEPTED,
                    SubmissionStatus.REJECTED,
                    SubmissionStatus.ERROR,
                    SubmissionStatus.DRY_RUN,
                }
            ):
                raise CorruptStateError(
                    f"invalid submission intent fields at index {index}"
                )
            seen_ids.add(submission_id)
            intents.append(record)
        return sorted(intents, key=self._submission_intent_sort_key)

    def _write_submission_intents(
        self,
        paths: ContestPaths,
        intents: Sequence[Mapping[str, Any]],
    ) -> None:
        ordered = [
            dict(record)
            for record in sorted(
                intents,
                key=self._submission_intent_sort_key,
            )
        ]
        atomic_write_json(
            paths.submission_intents,
            {
                "schema_version": SUBMISSION_INTENT_SCHEMA_VERSION,
                "contest_id": paths.root.name,
                "intents": ordered,
            },
        )

    def _load_contest_submission_records(
        self,
        paths: ContestPaths,
        *,
        repair_trailing_record: bool,
    ) -> tuple[list[dict[str, Any]], int, bool]:
        try:
            data = paths.submissions.read_bytes()
        except FileNotFoundError:
            return [], 0, False

        records: list[dict[str, Any]] = []
        trailing_bytes_removed = 0
        trailing_newline_added = False
        pieces = data.split(b"\n")
        has_trailing_fragment = bool(data) and not data.endswith(b"\n")
        for index, raw_line in enumerate(pieces, start=1):
            if not raw_line.strip():
                continue
            is_final_fragment = (
                has_trailing_fragment and index == len(pieces)
            )
            try:
                record = strict_json_loads(raw_line)
            except (UnicodeError, ValueError) as error:
                if repair_trailing_record and is_final_fragment:
                    separator = data.rfind(b"\n")
                    valid_prefix = data[: separator + 1] if separator >= 0 else b""
                    trailing_bytes_removed = len(data) - len(valid_prefix)
                    atomic_write_bytes(paths.submissions, valid_prefix)
                    break
                raise CorruptStateError(
                    f"invalid submissions.jsonl line {index}: {error}"
                ) from error
            if not isinstance(record, dict):
                raise CorruptStateError(
                    f"submissions.jsonl line {index} is not an object"
                )
            records.append(record)
            if repair_trailing_record and is_final_fragment:
                # A crash may leave a complete JSON object without its newline.
                # Normalize it before any later O_APPEND write.
                atomic_write_bytes(paths.submissions, data + b"\n")
                trailing_newline_added = True
        return records, trailing_bytes_removed, trailing_newline_added

    def _ledger_records_by_id(
        self,
        records: Sequence[Mapping[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        indexed: dict[str, dict[str, Any]] = {}
        for index, value in enumerate(records):
            submission_id = value.get("id")
            if not isinstance(submission_id, str) or not submission_id:
                raise CorruptStateError(
                    f"submission ledger record {index} has no valid id"
                )
            record = dict(value)
            previous = indexed.get(submission_id)
            if previous is not None and (
                self._submission_record_signature(previous)
                != self._submission_record_signature(record)
            ):
                raise CorruptStateError(
                    f"submission ledger id {submission_id!r} conflicts"
                )
            indexed.setdefault(submission_id, record)
        return indexed

    def _reconcile_submissions_locked(
        self,
        paths: ContestPaths,
    ) -> dict[str, Any]:
        intents = self._load_submission_intents(paths)
        records, removed_bytes, newline_added = (
            self._load_contest_submission_records(
                paths,
                repair_trailing_record=True,
            )
        )
        ledger_by_id = self._ledger_records_by_id(records)
        ledger_appended: list[str] = []
        stale_removed: list[str] = []
        completed_removed: list[str] = []
        remaining: list[dict[str, Any]] = []

        for intent in intents:
            submission_id = str(intent["id"])
            identity = ChallengeIdentity(
                str(intent["contest_id"]),
                str(intent["category"]),
                str(intent["challenge_id"]),
            )
            try:
                state = self.load(identity, recover=False)
            except StateNotFound:
                stale_removed.append(submission_id)
                continue
            submission = next(
                (
                    item
                    for item in state.submissions
                    if item.id == submission_id
                ),
                None,
            )
            if submission is None:
                stale_removed.append(submission_id)
                continue
            candidate = next(
                (
                    item
                    for item in state.candidates
                    if item.id == submission.candidate_id
                ),
                None,
            )
            expected_status = SubmissionStatus(str(intent["status"]))
            if (
                candidate is None
                or submission.candidate_id != intent["candidate_id"]
                or candidate.value != intent["flag"]
                or submission.status is not expected_status
                or submission.submitted_at != intent["recorded_at"]
                or submission.response != intent["response"]
                or submission.proof_passed is not intent["proof_passed"]
                or submission.format_ok is not intent["format_ok"]
                or submission.points != intent["points"]
                or (
                    submission.override.to_dict()
                    if submission.override is not None
                    else None
                )
                != intent.get("override")
                or state.revision < int(intent["state_revision"])
            ):
                remaining.append(intent)
                raise CorruptStateError(
                    f"submission intent {submission_id!r} does not match state"
                )

            existing = ledger_by_id.get(submission_id)
            if existing is not None:
                if (
                    self._submission_record_signature(existing)
                    != self._submission_record_signature(intent)
                ):
                    remaining.append(intent)
                    raise CorruptStateError(
                        f"submission intent {submission_id!r} conflicts "
                        "with the contest ledger"
                    )
            else:
                if expected_status is SubmissionStatus.ACCEPTED and any(
                    record.get("status")
                    == SubmissionStatus.ACCEPTED.value
                    and record.get("flag") == intent["flag"]
                    and (
                        record.get("category") != identity.category
                        or record.get("challenge_id")
                        != identity.challenge_id
                    )
                    for record in records
                ):
                    remaining.append(intent)
                    raise CorruptStateError(
                        "accepted submission intent conflicts with an "
                        "accepted flag for another challenge"
                    )
                append_json_line(paths.submissions, intent)
                record = dict(intent)
                records.append(record)
                ledger_by_id[submission_id] = record
                ledger_appended.append(submission_id)
            completed_removed.append(submission_id)

        if intents:
            self._write_submission_intents(paths, remaining)
        return {
            "contest_id": paths.root.name,
            "intents_seen": len(intents),
            "ledger_appended": ledger_appended,
            "completed_intents_removed": completed_removed,
            "stale_intents_removed": stale_removed,
            "remaining_intents": len(remaining),
            "ledger_trailing_bytes_removed": removed_bytes,
            "ledger_trailing_newline_added": newline_added,
        }

    def reconcile_submissions(self, contest_id: str) -> dict[str, Any]:
        """Repair submission ledger gaps left by an interrupted state commit.

        The durable intent is authoritative only when the referenced challenge
        state contains the exact submission. Missing state submissions make an
        intent stale; matching state submissions are appended idempotently.
        """

        paths = self.initialize_contest(contest_id)
        with FileLock(
            paths.runtime / "submissions.lock"
        ) as submissions_lock:
            submissions_lock.acquire()
            return self._reconcile_submissions_locked(paths)

    def load_contest_submissions(
        self, contest_id: str
    ) -> list[dict[str, Any]]:
        paths = self.initialize_contest(contest_id)
        with FileLock(
            paths.runtime / "submissions.lock"
        ) as submissions_lock:
            submissions_lock.acquire()
            self._reconcile_submissions_locked(paths)
            records, _removed, _normalized = (
                self._load_contest_submission_records(
                    paths,
                    repair_trailing_record=False,
                )
            )
            return records

    def record_submission(
        self,
        contest: str | ChallengeIdentity | ChallengeState,
        category: str | None = None,
        challenge_id: str | None = None,
        *,
        candidate_id: str,
        outcome: SubmissionStatus | str,
        response: str | None = None,
        submission_id: str | None = None,
        proof_passed: bool = False,
        format_ok: bool = True,
        points: int | float | None = None,  # noqa: PYI041 - mirrors model field
        override: SubmissionOverride | None = None,
        expected_revision: int | None = None,
    ) -> ChallengeState:
        """Persist a human-reported contest submission outcome.

        CTF-OS does not send the flag.  The operator submits it and records the
        accepted/rejected result here.  The flag remains in challenge state and
        the contest-wide JSONL record keeps the cross-challenge audit history.
        """

        self.assert_mutations_allowed()
        identity = _identity(contest, category, challenge_id)
        status = (
            outcome
            if isinstance(outcome, SubmissionStatus)
            else SubmissionStatus(str(outcome).lower())
        )
        if status not in {
            SubmissionStatus.ACCEPTED,
            SubmissionStatus.REJECTED,
            SubmissionStatus.ERROR,
            SubmissionStatus.DRY_RUN,
        }:
            raise ValueError("manual outcome cannot remain pending")

        def validate_outcome_transition(state: ChallengeState) -> None:
            if status is SubmissionStatus.ACCEPTED:
                validate_transition(
                    state.status,
                    ChallengeStatus.SOLVED,
                    evidence=TransitionEvidence(
                        operator_outcome="accepted"
                    ),
                )
                return
            if status is not SubmissionStatus.REJECTED:
                return
            if state.status in {
                ChallengeStatus.PROVING,
                ChallengeStatus.READY_TO_SUBMIT,
            }:
                validate_transition(
                    state.status,
                    ChallengeStatus.ACTIVE,
                    evidence=TransitionEvidence(
                        operator_outcome="rejected"
                    ),
                )
            elif (
                state.status is ChallengeStatus.PAUSED
                and state.resume_status
                in {
                    ChallengeStatus.PROVING,
                    ChallengeStatus.READY_TO_SUBMIT,
                }
            ):
                validate_transition(
                    state.resume_status,
                    ChallengeStatus.ACTIVE,
                    evidence=TransitionEvidence(
                        operator_outcome="rejected"
                    ),
                )

        submission_id = submission_id or (
            "SUB-" + uuid.uuid4().hex[:12]
        )
        contest_paths = self.initialize_contest(identity.contest_id)
        with FileLock(
            contest_paths.runtime / "submissions.lock"
        ) as submissions_lock:
            submissions_lock.acquire()
            # Repair any state-first commit from an interrupted prior writer
            # before checking accepted flags. A new writer cannot pass the
            # duplicate check while an earlier durable intent is unresolved.
            self._reconcile_submissions_locked(contest_paths)
            before = self.load(identity)
            expected = (
                before.revision
                if expected_revision is None
                else expected_revision
            )
            if expected != before.revision:
                raise RevisionConflict(expected, before.revision)
            candidate = next(
                (
                    item
                    for item in before.candidates
                    if item.id == candidate_id
                ),
                None,
            )
            if candidate is None:
                raise WorkerResultValidationError(
                    f"unknown candidate: {candidate_id}"
                )
            candidate_value = candidate.value
            history_records, _removed, _normalized = (
                self._load_contest_submission_records(
                    contest_paths,
                    repair_trailing_record=False,
                )
            )
            ledger_by_id = self._ledger_records_by_id(history_records)
            existing_state_submission = next(
                (
                    item
                    for item in before.submissions
                    if item.id == submission_id
                ),
                None,
            )
            existing_ledger_submission = ledger_by_id.get(submission_id)
            if existing_ledger_submission is not None:
                if (
                    existing_state_submission is None
                    or existing_state_submission.candidate_id != candidate_id
                    or existing_state_submission.status is not status
                    or existing_ledger_submission.get("contest_id")
                    != identity.contest_id
                    or existing_ledger_submission.get("category")
                    != identity.category
                    or existing_ledger_submission.get("challenge_id")
                    != identity.challenge_id
                    or existing_ledger_submission.get("candidate_id")
                    != candidate_id
                    or existing_ledger_submission.get("status")
                    != status.value
                ):
                    raise WorkerResultValidationError(
                        f"submission id {submission_id!r} was reused"
                    )
                return before
            accepted_submission_exists = any(
                item.candidate_id == candidate_id
                and item.status is SubmissionStatus.ACCEPTED
                for item in before.submissions
            )
            if (
                status is SubmissionStatus.ACCEPTED
                and before.status is ChallengeStatus.ABANDONED
            ):
                raise WorkerResultValidationError(
                    "an ABANDONED challenge cannot be reopened by a "
                    "submission outcome"
                )
            if (
                status is SubmissionStatus.REJECTED
                and (
                    candidate.status is CandidateStatus.ACCEPTED
                    or accepted_submission_exists
                )
            ):
                raise WorkerResultValidationError(
                    "an accepted candidate outcome is immutable"
                )
            if status == SubmissionStatus.ACCEPTED and any(
                record.get("status") == SubmissionStatus.ACCEPTED.value
                and record.get("flag") == candidate_value
                and (
                    record.get("category") != identity.category
                    or record.get("challenge_id") != identity.challenge_id
                )
                for record in history_records
            ):
                raise WorkerResultValidationError(
                    "this flag is already recorded as accepted for "
                    "another challenge"
                )

            recorded_at = utc_now()
            attempt = (
                sum(
                    item.candidate_id == candidate_id
                    for item in before.submissions
                )
                + (0 if existing_state_submission is not None else 1)
            )
            if existing_state_submission is not None:
                if (
                    existing_state_submission.candidate_id != candidate_id
                    or existing_state_submission.status is not status
                ):
                    raise WorkerResultValidationError(
                        f"submission id {submission_id!r} was reused"
                    )
                recorded_at = (
                    existing_state_submission.submitted_at or recorded_at
                )
                response = existing_state_submission.response
                proof_passed = existing_state_submission.proof_passed
                format_ok = existing_state_submission.format_ok
                points = existing_state_submission.points
                override = existing_state_submission.override

            # Reject an invalid serial lifecycle request before installing a
            # durable journal. The update mutator repeats the same validation
            # so a concurrent status change cannot bypass the sink gate.
            validate_outcome_transition(before)
            history = {
                "schema_version": SUBMISSION_LEDGER_RECORD_SCHEMA_VERSION,
                "id": submission_id,
                "recorded_at": recorded_at,
                **identity.to_dict(),
                "candidate_id": candidate_id,
                "flag": candidate_value,
                "status": status.value,
                "response": response,
                "proof_passed": proof_passed,
                "format_ok": format_ok,
                "points": points,
                "state_revision": (
                    before.revision
                    if existing_state_submission is not None
                    else before.revision + 1
                ),
            }
            if before.schema_version >= STATE_SCHEMA_VERSION:
                history["override"] = (
                    override.to_dict() if override is not None else None
                )
            # This atomic fsynced intent is installed before state.json changes.
            # It remains after any exception so the next record/status/reconcile
            # can deterministically decide whether to append or discard it.
            self._write_submission_intents(contest_paths, [history])

            def apply(state: ChallengeState) -> None:
                current_candidate = next(
                    (
                        item
                        for item in state.candidates
                        if item.id == candidate_id
                    ),
                    None,
                )
                if current_candidate is None:
                    raise WorkerResultValidationError(
                        f"unknown candidate: {candidate_id}"
                    )
                if current_candidate.value != candidate_value:
                    raise WorkerResultValidationError(
                        "candidate value changed during submission"
                    )
                if (
                    status is SubmissionStatus.ACCEPTED
                    and state.status is ChallengeStatus.ABANDONED
                ):
                    raise WorkerResultValidationError(
                        "an ABANDONED challenge cannot be reopened by a "
                        "submission outcome"
                    )
                if (
                    status is SubmissionStatus.REJECTED
                    and (
                        current_candidate.status
                        is CandidateStatus.ACCEPTED
                        or any(
                            item.candidate_id == candidate_id
                            and item.status
                            is SubmissionStatus.ACCEPTED
                            for item in state.submissions
                        )
                    )
                ):
                    raise WorkerResultValidationError(
                        "an accepted candidate outcome is immutable"
                    )
                existing = next(
                    (
                        item
                        for item in state.submissions
                        if item.id == submission_id
                    ),
                    None,
                )
                if existing is not None:
                    if (
                        existing.candidate_id != candidate_id
                        or existing.status != status
                    ):
                        raise WorkerResultValidationError(
                            f"submission id {submission_id!r} was reused"
                        )
                    return
                validate_outcome_transition(state)
                state.submissions.append(
                    SubmissionReference(
                        id=submission_id,
                        candidate_id=candidate_id,
                        status=status,
                        submitted_at=recorded_at,
                        response=response,
                        attempt=attempt,
                        proof_passed=proof_passed,
                        format_ok=format_ok,
                        points=points,
                        override=override,
                    )
                )
                if status == SubmissionStatus.ACCEPTED:
                    current_candidate.status = CandidateStatus.ACCEPTED
                    state.status = ChallengeStatus.SOLVED
                    state.resume_status = None
                    if state.schema_version >= STATE_SCHEMA_VERSION:
                        if state.active_goal is not None:
                            state.active_goal.status = GoalStatus.CANCELLED
                        state.active_goal_id = None
                        if state.active_managed_session_id is not None:
                            active_session = next(
                                (
                                    item
                                    for item in state.sessions
                                    if item.id
                                    == state.active_managed_session_id
                                ),
                                None,
                            )
                            if active_session is not None:
                                active_session.status = (
                                    SessionStatus.COMPLETED
                                )
                                active_session.stop_reason = (
                                    "manual accepted outcome"
                                )
                                active_session.end_revision = (
                                    state.revision + 1
                                )
                                active_session.ended_at = utc_now()
                            state.active_managed_session_id = None
                        if state.closure is None:
                            closure_id = (
                                "CLOSE-submission-"
                                + hashlib.sha256(
                                    (
                                        state.identity.key
                                        + "\0"
                                        + submission_id
                                    ).encode("utf-8")
                                ).hexdigest()[:16]
                            )
                            state.closure = ClosureBundle(
                                id=closure_id,
                                completeness=(
                                    ClosureCompleteness.INCOMPLETE
                                ),
                                portability="referential",
                                proof_run_ids=[
                                    item.id
                                    for item in state.runs
                                    if item.role == "proof"
                                ],
                                submission_ids=[submission_id],
                                target_ids=[
                                    item.id for item in state.targets
                                ],
                                checkpoint_ids=[
                                    item.id
                                    for item in state.checkpoints
                                ],
                                side_effect_receipt_ids=[
                                    item.id for item in state.receipts
                                ],
                                created_at=recorded_at,
                                extra={
                                    "automatic_incomplete": True,
                                    "reason": (
                                        "accepted truth was recorded before "
                                        "closure assembly"
                                    ),
                                },
                            )
                        elif submission_id not in (
                            state.closure.submission_ids
                        ):
                            state.closure.submission_ids.append(
                                submission_id
                            )
                elif status == SubmissionStatus.REJECTED:
                    current_candidate.status = CandidateStatus.REJECTED
                    if state.status in {
                        ChallengeStatus.PROVING,
                        ChallengeStatus.READY_TO_SUBMIT,
                    }:
                        state.status = ChallengeStatus.ACTIVE
                    elif (
                        state.status is ChallengeStatus.PAUSED
                        and state.resume_status
                        in {
                            ChallengeStatus.PROVING,
                            ChallengeStatus.READY_TO_SUBMIT,
                        }
                    ):
                        state.resume_status = ChallengeStatus.ACTIVE

            if existing_state_submission is None:
                committed = self.update(
                    identity,
                    apply,
                    expected_revision=before.revision,
                )
                if committed.revision != history["state_revision"]:
                    raise CorruptStateError(
                        "submission state revision did not match its intent"
                    )
            else:
                committed = before
            if submission_id not in ledger_by_id:
                append_json_line(contest_paths.submissions, history)
            self._write_submission_intents(contest_paths, [])
        return committed


__all__ = [
    "ArtifactValidationError",
    "ChallengePaths",
    "ContestPaths",
    "CorruptStateError",
    "InvalidIdentity",
    "RevisionConflict",
    "RunPaths",
    "StateAlreadyExists",
    "StateNotFound",
    "StateStore",
    "StateStoreError",
    "WorkerResultValidationError",
    "sha256_file",
    "validate_artifact",
]
