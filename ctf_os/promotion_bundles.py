"""Engine-collected blind/live promotion evidence bundles.

The existing :mod:`ctf_os.benchmark` module is deliberately a pure gate.  It
accepts typed evidence but cannot establish that an operator JSON document was
derived from canonical challenge state.  This module supplies that missing
boundary:

* an operator freezes the complete paired session manifest before collection;
* each invocation captures exactly one human-opened challenge session;
* the capture contains a bounded, content-addressed workspace projection;
* comparison re-hashes every file and re-runs the canonical evaluator; and
* only those re-derived attempts are passed to the pure promotion gate.

It never chooses a challenge, starts a model/tool, switches sessions, submits a
candidate, or mutates ``state.json``.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from ctf_os import evaluation as canonical_evaluation
from ctf_os.benchmark import (
    BLIND,
    CTF_OS_SYSTEM,
    DEV,
    HIDDEN,
    LIVE,
    REGRESSION,
    REQUIRED_PROMOTION_CATEGORIES,
    THIN_SCAFFOLD,
    BenchmarkExecutionFingerprint,
    BlindLivePromotionEvidence,
    FixedBenchmarkBudget,
    PromotionArm,
    PromotionAttempt,
    PromotionCase,
    PromotionCaseResult,
    PromotionSplit,
    SafetyTotals,
    evaluate_blind_live_promotion,
)
from ctf_os.codex import (
    LIVE_THIN_SCAFFOLD,
    LiveCommandBuilder,
    LiveSession,
    ModelCatalog,
    ReasoningEffort,
)
from ctf_os.evaluation import EvaluationReport, evaluate_workspace
from ctf_os.config import EngineConfig, load_config
from ctf_os.knowledge import KnowledgeError, KnowledgeStore
from ctf_os.managed_continuity import (
    THREAD_CONTINUITY_SESSION_KEY,
    valid_thread_id,
)
from ctf_os.models import (
    BudgetMode,
    ChallengeIdentity,
    ChallengeState,
    ExperimentKind,
    ExperimentStatus,
    RunOrigin,
    RunReference,
    RunStatus,
    SessionMode,
    SubmissionStatus,
    utc_now,
)
from ctf_os.scaffold_binding import (
    SCAFFOLD_LAUNCH_METADATA_KEY,
    ScaffoldBindingError,
    managed_command_contract_sha256,
    parse_scaffold_launch_record,
)
from ctf_os.runtime_source import (
    RuntimeSourceError,
    RuntimeSourceInventory,
    runtime_source_inventory,
)
from ctf_os.store import StateStore
from ctf_os.store.atomic import (
    atomic_write_bytes,
    atomic_write_json,
    canonical_json_bytes,
    strict_json_loads,
)
from ctf_os.store.upgrades import upgrade_state, validate_state_protocol_shape
from ctf_os.stages.ingest import IngestError, inventory_challenge


PROMOTION_MANIFEST_SCHEMA_VERSION = 2
PROMOTION_BUNDLE_SCHEMA_VERSION = 3
PROMOTION_SIGNATURE_SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_BUNDLE_INDEX_BYTES = 4 * 1024 * 1024
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_CAPTURE_FILE_BYTES = 32 * 1024 * 1024
MAX_CAPTURE_TOTAL_BYTES = 128 * 1024 * 1024
MAX_CAPTURE_FILES = 4096
MAX_IDENTIFIER_BYTES = 256
MAX_CASES = 4096
MAX_SESSIONS = MAX_CASES * 6
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_TERMINAL_RUN_STATUSES = frozenset(
    {
        RunStatus.COMPLETED,
        RunStatus.INVALID,
        RunStatus.FAILED,
        RunStatus.TIMED_OUT,
        RunStatus.CANCELLED,
        RunStatus.INTERRUPTED,
    }
)
_ARMS = frozenset({THIN_SCAFFOLD, CTF_OS_SYSTEM})
_SPLITS = frozenset({DEV, REGRESSION, BLIND, LIVE, HIDDEN})
_KEY_RELATIVE_PATH = Path("runtime") / "promotion-bundle.key"
_MANIFEST_DOMAIN = b"ctfos-promotion-manifest-v1\0"
_BUNDLE_DOMAIN = b"ctfos-promotion-bundle-v1\0"
_EMPTY_KNOWLEDGE_SNAPSHOT = {
    "schema_version": 1,
    "documents": [],
}
_EMPTY_KNOWLEDGE_SNAPSHOT_SHA256 = hashlib.sha256(
    canonical_json_bytes(_EMPTY_KNOWLEDGE_SNAPSHOT)
).hexdigest()
_INITIAL_CONTEXT_SCHEMA_VERSION = 1
_OPERATOR_INPUT_SCHEMA_VERSION = 1
_OPERATOR_INPUT_INVENTORY_SCHEMA_VERSION = 1
_MODEL_ROLE_FIELDS = (
    "captain",
    "recon",
    "specialist",
    "builder",
    "falsifier",
    "extractor",
    "reproducer",
    "validator",
    "evidence_auditor",
)


class PromotionBundleError(ValueError):
    """A manifest, canonical session, or capture failed closed."""


@dataclass(frozen=True, slots=True)
class ManifestSession:
    session_id: str
    arm: str
    attempt: int
    contest_id: str
    category: str
    challenge_id: str
    case_id: str
    split: str
    input_manifest_sha256: str

    @property
    def identity(self) -> ChallengeIdentity:
        return ChallengeIdentity(
            self.contest_id,
            self.category,
            self.challenge_id,
        )


@dataclass(frozen=True, slots=True)
class ParsedManifest:
    raw: dict[str, object]
    benchmark_id: str
    model_id: str
    budget: FixedBenchmarkBudget
    fingerprint: BenchmarkExecutionFingerprint
    splits: tuple[PromotionSplit, ...]
    sessions: Mapping[str, ManifestSession]

    @property
    def manifest_sha256(self) -> str:
        return _sha256(canonical_json_bytes(self.raw))


@dataclass(frozen=True, slots=True)
class VerifiedBundle:
    record: Mapping[str, object]
    session: ManifestSession
    state: ChallengeState
    report: EvaluationReport
    attempt: PromotionAttempt
    safety: SafetyTotals
    complete: bool
    blockers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _CandidateBinding:
    candidate_id: str
    value_sha256: str


@dataclass(frozen=True, slots=True)
class _CandidateProofEvidence:
    binding: _CandidateBinding
    passed: bool
    successful_attempts: int
    total_attempts: int
    completed_at: str
    run_ids: tuple[str, ...]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _strict_mapping(
    value: object,
    *,
    keys: frozenset[str],
    label: str,
) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != keys:
        raise PromotionBundleError(
            f"{label} must contain exactly the required fields"
        )
    return value


def _strict_list(
    value: object,
    *,
    label: str,
    maximum: int,
    nonempty: bool = False,
) -> list[object]:
    if (
        type(value) is not list
        or len(value) > maximum
        or (nonempty and not value)
    ):
        qualifier = "non-empty " if nonempty else ""
        raise PromotionBundleError(
            f"{label} must be a bounded {qualifier}list"
        )
    return value


def _identifier(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value.encode("utf-8", errors="strict")) > MAX_IDENTIFIER_BYTES
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F
            for character in value
        )
        or "/" in value
        or "\\" in value
        or value in {".", ".."}
    ):
        raise PromotionBundleError(
            f"{label} must be a safe bounded non-empty identifier"
        )
    return value


def _sha256_value(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise PromotionBundleError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _exact_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise PromotionBundleError(f"{label} must be a boolean")
    return value


def _count(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = (1 << 63) - 1,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise PromotionBundleError(
            f"{label} must be an integer within {minimum}..{maximum}"
        )
    return value


def _parse_timestamp(value: object, label: str) -> str:
    if type(value) is not str or not value.endswith("Z"):
        raise PromotionBundleError(f"{label} must be a UTC Z timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise PromotionBundleError(
            f"{label} must be a valid UTC timestamp"
        ) from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise PromotionBundleError(f"{label} must be UTC")
    return value


def _timestamp_epoch(value: object) -> float | None:
    if type(value) is not str or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        return None
    return parsed.timestamp()


def _evaluation_utc_now() -> str:
    """Keep lifecycle endpoints precise enough for exact deadline envelopes."""

    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _epoch_delta(later_epoch: float, earlier_epoch: float) -> float:
    """Subtract microsecond timestamps without binary epoch drift."""

    return round(later_epoch - earlier_epoch, 6)


def _require_evaluation_clock_binding(
    state: ChallengeState,
    *,
    wall_seconds: int,
) -> tuple[float, float]:
    """Return the bound evaluation start/deadline or fail closed."""

    if (
        state.budget.mode is not BudgetMode.BOUNDED
        or type(state.budget.allocated_seconds) is not int
        or state.budget.allocated_seconds != wall_seconds
    ):
        raise PromotionBundleError(
            "promotion evaluation requires the frozen bounded canonical budget"
        )
    started_at = state.metadata.get("evaluation_started_at")
    bound_deadline = state.metadata.get(
        "evaluation_budget_deadline_utc"
    )
    start_epoch = _timestamp_epoch(started_at)
    deadline_epoch = _timestamp_epoch(bound_deadline)
    if start_epoch is None:
        raise PromotionBundleError(
            "evaluation_started_at must be a valid UTC timestamp"
        )
    if deadline_epoch is None:
        raise PromotionBundleError(
            "evaluation_budget_deadline_utc must be a valid UTC timestamp"
        )
    if state.budget.deadline_utc != bound_deadline:
        raise PromotionBundleError(
            "canonical budget deadline differs from the prepared evaluation "
            "deadline"
        )
    if (
        deadline_epoch <= start_epoch
        or _epoch_delta(deadline_epoch, start_epoch) > wall_seconds
    ):
        raise PromotionBundleError(
            "prepared evaluation deadline must follow its start within the "
            "frozen fixed wall budget"
        )
    return start_epoch, deadline_epoch


def _activity_timestamps(state: ChallengeState) -> tuple[object, ...]:
    return (
        *(run.created_at for run in state.runs),
        *(artifact.created_at for artifact in state.artifacts),
        *(candidate.created_at for candidate in state.candidates),
        *(submission.submitted_at for submission in state.submissions),
    )


def _require_activity_window(
    state: ChallengeState,
    *,
    start_epoch: float,
    finalized_epoch: float,
) -> None:
    for timestamp in _activity_timestamps(state):
        epoch = _timestamp_epoch(timestamp)
        if epoch is None:
            raise PromotionBundleError(
                "promotion activity timestamps must be valid UTC timestamps"
            )
        if epoch < start_epoch:
            raise PromotionBundleError(
                "promotion activity cannot precede evaluation_started_at"
            )
        if epoch > finalized_epoch:
            raise PromotionBundleError(
                "promotion activity cannot follow evaluation_finalized_at"
            )


def _parse_budget(value: object) -> FixedBenchmarkBudget:
    raw = _strict_mapping(
        value,
        keys=frozenset(
            {"wall_seconds", "model_call_limit", "total_token_limit"}
        ),
        label="promotion manifest budget",
    )
    budget = FixedBenchmarkBudget(
        wall_seconds=_count(
            raw["wall_seconds"],
            "budget wall_seconds",
            minimum=1,
        ),
        model_call_limit=_count(
            raw["model_call_limit"],
            "budget model_call_limit",
            minimum=1,
        ),
        total_token_limit=_count(
            raw["total_token_limit"],
            "budget total_token_limit",
            minimum=1,
        ),
    )
    budget.validate()
    return budget


def _parse_fingerprint(
    value: object,
) -> BenchmarkExecutionFingerprint:
    raw = _strict_mapping(
        value,
        keys=frozenset(
            {
                "tool_manifest_sha256",
                "image_sha256",
                "model_config_sha256",
                "engine_source_sha256",
            }
        ),
        label="promotion execution fingerprint",
    )
    result = BenchmarkExecutionFingerprint(
        tool_manifest_sha256=_sha256_value(
            raw["tool_manifest_sha256"],
            "tool_manifest_sha256",
        ),
        image_sha256=_sha256_value(
            raw["image_sha256"],
            "image_sha256",
        ),
        model_config_sha256=_sha256_value(
            raw["model_config_sha256"],
            "model_config_sha256",
        ),
        engine_source_sha256=_sha256_value(
            raw["engine_source_sha256"],
            "engine_source_sha256",
        ),
    )
    result.validate()
    return result


def parse_promotion_manifest(value: object) -> ParsedManifest:
    """Parse the exact pre-run paired-session manifest.

    A case owns precisely three distinct sessions for each arm.  Consequently
    provider concurrency can delay sessions, but cannot silently reduce the
    logical repeat count.
    """

    raw = _strict_mapping(
        value,
        keys=frozenset(
            {
                "schema_version",
                "benchmark_id",
                "model_id",
                "budget",
                "execution_fingerprint",
                "splits",
            }
        ),
        label="promotion manifest",
    )
    if (
        type(raw["schema_version"]) is not int
        or raw["schema_version"] != PROMOTION_MANIFEST_SCHEMA_VERSION
    ):
        raise PromotionBundleError(
            "unsupported promotion manifest schema"
        )
    benchmark_id = _identifier(raw["benchmark_id"], "benchmark_id")
    model_id = _identifier(raw["model_id"], "model_id")
    budget = _parse_budget(raw["budget"])
    fingerprint = _parse_fingerprint(raw["execution_fingerprint"])
    raw_splits = _strict_list(
        raw["splits"],
        label="promotion splits",
        maximum=len(_SPLITS),
        nonempty=True,
    )

    split_names: set[str] = set()
    case_ids: set[str] = set()
    input_digests: set[str] = set()
    session_ids: set[str] = set()
    identities: set[tuple[str, str, str]] = set()
    sessions: dict[str, ManifestSession] = {}
    splits: list[PromotionSplit] = []
    total_cases = 0
    for raw_split_value in raw_splits:
        raw_split = _strict_mapping(
            raw_split_value,
            keys=frozenset(
                {
                    "name",
                    "trajectory_visible",
                    "answers_visible",
                    "prior_engine_runs",
                    "cases",
                }
            ),
            label="promotion manifest split",
        )
        name = raw_split["name"]
        if type(name) is not str or name not in _SPLITS:
            raise PromotionBundleError("unknown promotion split")
        if name in split_names:
            raise PromotionBundleError(
                "promotion split names must be unique"
            )
        split_names.add(name)
        trajectory_visible = _exact_bool(
            raw_split["trajectory_visible"],
            f"{name} trajectory_visible",
        )
        answers_visible = _exact_bool(
            raw_split["answers_visible"],
            f"{name} answers_visible",
        )
        prior_engine_runs = _count(
            raw_split["prior_engine_runs"],
            f"{name} prior_engine_runs",
        )
        if name == DEV:
            if not trajectory_visible:
                raise PromotionBundleError(
                    "dev trajectory must be visible before freeze"
                )
        elif trajectory_visible:
            raise PromotionBundleError(
                f"{name} trajectory leakage cannot be frozen"
            )
        if answers_visible:
            raise PromotionBundleError(
                f"{name} answer visibility cannot be frozen"
            )
        if name == REGRESSION:
            if prior_engine_runs == 0:
                raise PromotionBundleError(
                    "regression must record prior engine exposure"
                )
        elif name in {BLIND, LIVE, HIDDEN} and prior_engine_runs != 0:
            raise PromotionBundleError(
                f"{name} prior exposure cannot be frozen"
            )

        raw_cases = _strict_list(
            raw_split["cases"],
            label=f"{name} cases",
            maximum=MAX_CASES,
            nonempty=True,
        )
        split_cases: list[PromotionCase] = []
        for raw_case_value in raw_cases:
            total_cases += 1
            if total_cases > MAX_CASES:
                raise PromotionBundleError(
                    "promotion manifest exceeds the case limit"
                )
            raw_case = _strict_mapping(
                raw_case_value,
                keys=frozenset(
                    {
                        "case_id",
                        "category",
                        "input_manifest_sha256",
                        "sessions",
                    }
                ),
                label="promotion manifest case",
            )
            case_id = _identifier(raw_case["case_id"], "case_id")
            category = raw_case["category"]
            if (
                type(category) is not str
                or category not in REQUIRED_PROMOTION_CATEGORIES
            ):
                raise PromotionBundleError(
                    "case category must be canonical"
                )
            input_digest = _sha256_value(
                raw_case["input_manifest_sha256"],
                "input_manifest_sha256",
            )
            if case_id in case_ids:
                raise PromotionBundleError(
                    "promotion case_ids must be globally unique"
                )
            if input_digest in input_digests:
                raise PromotionBundleError(
                    "input manifest digests must be globally unique"
                )
            case_ids.add(case_id)
            input_digests.add(input_digest)
            raw_sessions = _strict_list(
                raw_case["sessions"],
                label=f"{case_id} sessions",
                maximum=6,
                nonempty=True,
            )
            seen_arm_attempts: set[tuple[str, int]] = set()
            for raw_session_value in raw_sessions:
                raw_session = _strict_mapping(
                    raw_session_value,
                    keys=frozenset(
                        {
                            "session_id",
                            "arm",
                            "attempt",
                            "contest_id",
                            "category",
                            "challenge_id",
                        }
                    ),
                    label="promotion manifest session",
                )
                session_id = _identifier(
                    raw_session["session_id"],
                    "session_id",
                )
                arm = raw_session["arm"]
                if type(arm) is not str or arm not in _ARMS:
                    raise PromotionBundleError(
                        "session arm must be thin_scaffold or ctf_os"
                    )
                attempt = _count(
                    raw_session["attempt"],
                    "session attempt",
                    minimum=1,
                    maximum=3,
                )
                contest_id = _identifier(
                    raw_session["contest_id"],
                    "session contest_id",
                )
                session_category = raw_session["category"]
                if (
                    type(session_category) is not str
                    or session_category != category
                ):
                    raise PromotionBundleError(
                        "session category must equal its case category"
                    )
                challenge_id = _identifier(
                    raw_session["challenge_id"],
                    "session challenge_id",
                )
                arm_attempt = (arm, attempt)
                identity_key = (
                    contest_id,
                    session_category,
                    challenge_id,
                )
                if arm_attempt in seen_arm_attempts:
                    raise PromotionBundleError(
                        "arm/attempt pairs must be unique per case"
                    )
                if session_id in session_ids:
                    raise PromotionBundleError(
                        "session_ids must be globally unique"
                    )
                if identity_key in identities:
                    raise PromotionBundleError(
                        "one canonical challenge identity cannot represent "
                        "multiple benchmark sessions"
                    )
                seen_arm_attempts.add(arm_attempt)
                session_ids.add(session_id)
                identities.add(identity_key)
                sessions[session_id] = ManifestSession(
                    session_id=session_id,
                    arm=arm,
                    attempt=attempt,
                    contest_id=contest_id,
                    category=session_category,
                    challenge_id=challenge_id,
                    case_id=case_id,
                    split=name,
                    input_manifest_sha256=input_digest,
                )
            required = {
                (arm, attempt)
                for arm in sorted(_ARMS)
                for attempt in (1, 2, 3)
            }
            if seen_arm_attempts != required:
                raise PromotionBundleError(
                    f"{case_id} must predeclare exactly three sessions per arm"
                )
            split_cases.append(
                PromotionCase(
                    case_id=case_id,
                    category=category,
                    input_manifest_sha256=input_digest,
                )
            )
        split = PromotionSplit(
            name=name,
            cases=tuple(split_cases),
            trajectory_visible=trajectory_visible,
            answers_visible=answers_visible,
            prior_engine_runs=prior_engine_runs,
        )
        split.validate()
        splits.append(split)

    required_splits = {DEV, REGRESSION, BLIND, LIVE}
    missing_splits = sorted(required_splits - split_names)
    if missing_splits:
        raise PromotionBundleError(
            "manifest is missing required splits: "
            + ", ".join(missing_splits)
        )
    if len(sessions) > MAX_SESSIONS:
        raise PromotionBundleError(
            "promotion manifest exceeds the session limit"
        )
    return ParsedManifest(
        raw=raw,
        benchmark_id=benchmark_id,
        model_id=model_id,
        budget=budget,
        fingerprint=fingerprint,
        splits=tuple(splits),
        sessions=sessions,
    )


def _read_regular(
    path: Path,
    *,
    maximum: int,
    label: str,
) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PromotionBundleError(
            f"{label} cannot be opened safely"
        ) from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise PromotionBundleError(
                f"{label} must be a regular file"
            )
        if before.st_size > maximum:
            raise PromotionBundleError(
                f"{label} exceeds {maximum} bytes"
            )
        payload = bytearray()
        while len(payload) <= maximum:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, maximum + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            before_identity != after_identity
            or len(payload) != after.st_size
            or len(payload) > maximum
        ):
            raise PromotionBundleError(
                f"{label} changed while it was read"
            )
        return bytes(payload)
    except OSError as error:
        raise PromotionBundleError(
            f"{label} cannot be read safely"
        ) from error
    finally:
        os.close(descriptor)


def _load_json_file(
    path: Path,
    *,
    maximum: int,
    label: str,
) -> object:
    try:
        return strict_json_loads(
            _read_regular(path, maximum=maximum, label=label),
            max_bytes=maximum,
        )
    except (UnicodeError, ValueError) as error:
        if isinstance(error, PromotionBundleError):
            raise
        raise PromotionBundleError(f"{label} is not strict JSON") from error


def _key_path(workspace_root: Path) -> Path:
    return workspace_root / ".ctfos" / _KEY_RELATIVE_PATH


def _load_key(workspace_root: Path, *, create: bool) -> bytes:
    path = _key_path(workspace_root)
    if create:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path.parent, 0o700)
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError:
            pass
        except OSError as error:
            raise PromotionBundleError(
                "promotion collector key cannot be created"
            ) from error
        else:
            try:
                key = os.urandom(32)
                written = os.write(descriptor, key)
                if written != len(key):
                    raise PromotionBundleError(
                        "promotion collector key write was incomplete"
                    )
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    payload = _read_regular(
        path,
        maximum=64,
        label="promotion collector key",
    )
    metadata = path.stat(follow_symlinks=False)
    if (
        len(payload) != 32
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise PromotionBundleError(
            "promotion collector key must be a private 32-byte file"
        )
    return payload


def _signature(key: bytes, domain: bytes, value: object) -> str:
    return hmac.new(
        key,
        domain + canonical_json_bytes(value),
        hashlib.sha256,
    ).hexdigest()


def _refuse_existing(path: Path, label: str) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise PromotionBundleError(f"{label} already exists")


def freeze_promotion_manifest(
    workspace_root: Path | str,
    manifest_path: Path | str,
    output_path: Path | str,
) -> dict[str, object]:
    """Validate and locally authenticate a pre-run promotion manifest."""

    workspace = Path(workspace_root).resolve()
    manifest_source = Path(manifest_path)
    output = Path(output_path)
    _refuse_existing(output, "frozen manifest output")
    parsed = parse_promotion_manifest(
        _load_json_file(
            manifest_source,
            maximum=MAX_MANIFEST_BYTES,
            label="promotion manifest",
        )
    )
    if local_execution_fingerprint(workspace) != parsed.fingerprint:
        raise PromotionBundleError(
            "current execution fingerprint differs from the manifest"
        )
    frozen_at = utc_now()
    unsigned = {
        "schema_version": PROMOTION_SIGNATURE_SCHEMA_VERSION,
        "frozen_at": frozen_at,
        "manifest": parsed.raw,
        "manifest_sha256": parsed.manifest_sha256,
    }
    key = _load_key(workspace, create=True)
    envelope = {
        **unsigned,
        "hmac_sha256": _signature(
            key,
            _MANIFEST_DOMAIN,
            unsigned,
        ),
    }
    if local_execution_fingerprint(workspace) != parsed.fingerprint:
        raise PromotionBundleError(
            "execution fingerprint changed during manifest freeze"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(output, envelope, mode=0o400)
    return {
        "schema_version": PROMOTION_SIGNATURE_SCHEMA_VERSION,
        "frozen": True,
        "benchmark_id": parsed.benchmark_id,
        "manifest_sha256": parsed.manifest_sha256,
        "sessions": len(parsed.sessions),
        "output": str(output),
        "automatic_promotion": False,
    }


def _load_frozen_manifest(
    workspace_root: Path,
    path: Path,
) -> tuple[ParsedManifest, str]:
    envelope = _strict_mapping(
        _load_json_file(
            path,
            maximum=MAX_MANIFEST_BYTES,
            label="frozen promotion manifest",
        ),
        keys=frozenset(
            {
                "schema_version",
                "frozen_at",
                "manifest",
                "manifest_sha256",
                "hmac_sha256",
            }
        ),
        label="frozen promotion manifest",
    )
    if (
        type(envelope["schema_version"]) is not int
        or envelope["schema_version"] != PROMOTION_SIGNATURE_SCHEMA_VERSION
    ):
        raise PromotionBundleError(
            "unsupported frozen promotion manifest schema"
        )
    frozen_at = _parse_timestamp(
        envelope["frozen_at"],
        "frozen_at",
    )
    manifest = parse_promotion_manifest(envelope["manifest"])
    claimed_digest = _sha256_value(
        envelope["manifest_sha256"],
        "manifest_sha256",
    )
    if claimed_digest != manifest.manifest_sha256:
        raise PromotionBundleError(
            "frozen manifest digest does not match its content"
        )
    claimed_signature = _sha256_value(
        envelope["hmac_sha256"],
        "manifest hmac_sha256",
    )
    unsigned = {
        key: envelope[key]
        for key in (
            "schema_version",
            "frozen_at",
            "manifest",
            "manifest_sha256",
        )
    }
    key = _load_key(workspace_root, create=False)
    expected = _signature(key, _MANIFEST_DOMAIN, unsigned)
    if not hmac.compare_digest(claimed_signature, expected):
        raise PromotionBundleError(
            "frozen manifest authentication failed"
        )
    return manifest, frozen_at


def _local_execution_fingerprint(
    workspace_root: Path | str,
) -> tuple[BenchmarkExecutionFingerprint, RuntimeSourceInventory]:
    """Derive the local fingerprint and its exact runtime-source inventory."""

    workspace = Path(workspace_root).resolve()
    config = load_config(workspace)
    image_digest = config.runtime.image_digest
    if (
        type(image_digest) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest) is None
    ):
        raise PromotionBundleError(
            "benchmark sessions require a pinned runtime image digest"
        )
    tool_manifest_path = (
        Path(__file__).resolve().parent.parent
        / "ctf-os-image"
        / "capabilities.v2.json"
    )
    tool_manifest = _read_regular(
        tool_manifest_path,
        maximum=MAX_MANIFEST_BYTES,
        label="CTF image capability manifest",
    )
    try:
        source_inventory = runtime_source_inventory()
    except RuntimeSourceError as error:
        raise PromotionBundleError(
            "CTF-OS runtime source inventory is not clean and stable"
        ) from error
    model_configuration = asdict(config.models)
    result = BenchmarkExecutionFingerprint(
        tool_manifest_sha256=_sha256(tool_manifest),
        image_sha256=image_digest.removeprefix("sha256:"),
        model_config_sha256=_sha256(
            canonical_json_bytes(model_configuration)
        ),
        engine_source_sha256=source_inventory.sha256,
    )
    result.validate()
    return result, source_inventory


def local_execution_fingerprint(
    workspace_root: Path | str,
) -> BenchmarkExecutionFingerprint:
    """Derive the model/tool/image/source fingerprint used for promotion."""

    fingerprint, _inventory = _local_execution_fingerprint(
        workspace_root
    )
    return fingerprint


def execution_fingerprint_report(
    workspace_root: Path | str,
) -> dict[str, object]:
    """Return the exact values an operator should freeze into a manifest."""

    fingerprint, source_inventory = _local_execution_fingerprint(
        workspace_root
    )
    config = load_config(Path(workspace_root).resolve())
    model_ids = {
        getattr(config.models, field)
        for field in _MODEL_ROLE_FIELDS
    }
    return {
        "schema_version": PROMOTION_MANIFEST_SCHEMA_VERSION,
        "model_ids": sorted(model_ids),
        "single_model": len(model_ids) == 1,
        "execution_fingerprint": {
            "tool_manifest_sha256": (
                fingerprint.tool_manifest_sha256
            ),
            "image_sha256": fingerprint.image_sha256,
            "model_config_sha256": (
                fingerprint.model_config_sha256
            ),
            "engine_source_sha256": (
                fingerprint.engine_source_sha256
            ),
        },
        "engine_source_inventory": source_inventory.to_dict(),
    }


def _without_volatile_fields(
    value: Mapping[str, object],
    *fields: str,
) -> dict[str, object]:
    excluded = frozenset(fields)
    return {
        key: item
        for key, item in value.items()
        if key not in excluded
    }


def _initial_context_sha256(state: ChallengeState) -> str:
    """Hash the operator-visible pre-run context across paired sessions.

    Session identity, timestamps, state revisions, and budget deadlines differ
    by construction.  Everything that can materially change the initial model
    context is retained, while those volatile fields are removed.
    """

    metadata = {
        key: value
        for key, value in state.metadata.items()
        if not key.startswith("evaluation_")
        and key != "human_intervention_count"
        and key != "budget_reset_at"
    }
    goals = [
        _without_volatile_fields(goal.to_dict(), "created_at")
        for goal in state.goals
    ]
    experiments = [
        _without_volatile_fields(
            experiment.to_dict(v2=state.schema_version >= 2),
            "created_at",
        )
        for experiment in state.experiments
    ]
    targets = [
        _without_volatile_fields(
            target.to_dict(),
            "created_at",
            "last_preflight",
        )
        for target in state.targets
    ]
    document = {
        "schema_version": _INITIAL_CONTEXT_SCHEMA_VERSION,
        "category": state.category,
        "status": state.status.value,
        "description": state.description,
        "prompt": state.prompt,
        "source_inventory": [
            source.to_dict() for source in state.source_inventory
        ],
        "metadata": metadata,
        "active_goal_id": state.active_goal_id,
        "goals": goals,
        "experiments": experiments,
        "targets": targets,
        "primary_target_id": state.primary_target_id,
        "configuration_epoch": state.configuration_epoch,
        "budget": {
            "allocated_seconds": state.budget.allocated_seconds,
            "model_tier": state.budget.model_tier,
            "abort_rule": dict(state.budget.abort_rule),
            "curve_profile": state.budget.curve_profile,
            "mode": state.budget.mode.value,
        },
        "state_extra": dict(state.extra),
    }
    return _sha256(canonical_json_bytes(document))


def _incoming_challenge_root(
    workspace: Path,
    identity: ChallengeIdentity,
) -> Path:
    incoming_root = load_config(workspace).incoming_root.resolve(
        strict=False
    )
    candidate = (
        incoming_root
        / identity.contest_id
        / identity.category
        / identity.challenge_id
    )
    try:
        candidate.resolve(strict=False).relative_to(incoming_root)
    except ValueError as error:
        raise PromotionBundleError(
            "promotion challenge input escapes incoming/"
        ) from error
    return candidate


def _state_source_records(
    state: ChallengeState,
) -> list[dict[str, object]]:
    return [source.to_dict() for source in state.source_inventory]


def _incoming_inventory_summary(
    workspace: Path,
    state: ChallengeState,
) -> dict[str, object]:
    try:
        inventory = inventory_challenge(
            _incoming_challenge_root(workspace, state.identity)
        )
    except (IngestError, OSError, ValueError) as error:
        raise PromotionBundleError(
            "promotion immutable incoming input could not be inventoried"
        ) from error
    files = [
        {
            "path": source.path,
            "sha256": source.sha256,
            "size": source.size,
        }
        for source in inventory.files
    ]
    state_files = [
        {
            "path": source.path,
            "sha256": source.sha256,
            "size": source.size,
        }
        for source in state.source_inventory
    ]
    if state_files != files:
        raise PromotionBundleError(
            "canonical source inventory differs from immutable incoming bytes"
        )
    if (
        state.metadata.get("source_manifest_sha256")
        != inventory.manifest_sha256
        or state.metadata.get("source_total_bytes")
        != inventory.total_bytes
    ):
        raise PromotionBundleError(
            "canonical source metadata differs from immutable incoming bytes"
        )
    return {
        "schema_version": _OPERATOR_INPUT_INVENTORY_SCHEMA_VERSION,
        "manifest_sha256": inventory.manifest_sha256,
        "files_sha256": _sha256(canonical_json_bytes(files)),
        "file_count": len(files),
        "total_bytes": inventory.total_bytes,
    }


def _operator_input_document(
    state: ChallengeState,
    incoming: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema_version": _OPERATOR_INPUT_SCHEMA_VERSION,
        "category": state.category,
        "description": state.description,
        "prompt": state.prompt,
        "incoming_inventory": dict(incoming),
        "static_source": {
            "source_manifest_sha256": state.metadata.get(
                "source_manifest_sha256"
            ),
            "source_total_bytes": state.metadata.get(
                "source_total_bytes"
            ),
            "source_inventory": _state_source_records(state),
        },
    }


def _parse_operator_input_inventory(
    value: object,
) -> dict[str, object]:
    raw = _strict_mapping(
        value,
        keys=frozenset(
            {
                "schema_version",
                "manifest_sha256",
                "files_sha256",
                "file_count",
                "total_bytes",
            }
        ),
        label="operator input inventory",
    )
    if (
        type(raw["schema_version"]) is not int
        or raw["schema_version"]
        != _OPERATOR_INPUT_INVENTORY_SCHEMA_VERSION
    ):
        raise PromotionBundleError(
            "operator input inventory has an invalid schema"
        )
    result = {
        "schema_version": raw["schema_version"],
        "manifest_sha256": _sha256_value(
            raw["manifest_sha256"],
            "operator input manifest_sha256",
        ),
        "files_sha256": _sha256_value(
            raw["files_sha256"],
            "operator input files_sha256",
        ),
        "file_count": _count(
            raw["file_count"],
            "operator input file_count",
        ),
        "total_bytes": _count(
            raw["total_bytes"],
            "operator input total_bytes",
        ),
    }
    return result


def _operator_input_sha256(
    state: ChallengeState,
    incoming: Mapping[str, object],
) -> str:
    return _sha256(
        canonical_json_bytes(_operator_input_document(state, incoming))
    )


def require_promotion_operator_input(
    workspace_root: Path | str,
    state: ChallengeState,
    *,
    captured_inventory: object | None = None,
) -> dict[str, object]:
    """Re-attest immutable operator input without hashing solve trajectory."""

    expected_schema = state.metadata.get(
        "evaluation_operator_input_schema_version"
    )
    expected_sha256 = state.metadata.get(
        "evaluation_operator_input_sha256"
    )
    if (
        expected_schema != _OPERATOR_INPUT_SCHEMA_VERSION
        or type(expected_sha256) is not str
        or _SHA256_RE.fullmatch(expected_sha256) is None
    ):
        raise PromotionBundleError(
            "promotion operator input commitment is missing or invalid"
        )
    incoming = (
        _incoming_inventory_summary(
            Path(workspace_root).resolve(),
            state,
        )
        if captured_inventory is None
        else _parse_operator_input_inventory(captured_inventory)
    )
    observed = _operator_input_sha256(state, incoming)
    if not hmac.compare_digest(observed, expected_sha256):
        raise PromotionBundleError(
            "promotion operator input differs from the prepared commitment"
        )
    return incoming


def _require_clean_preexecution_context(state: ChallengeState) -> None:
    """Reject solve-derived state while preserving deterministic ingest seeds."""

    contaminated = [
        name
        for name, values in (
            ("facts", state.facts),
            ("hypotheses", state.hypotheses),
            ("progress_markers", state.progress_markers),
            ("artifacts", state.artifacts),
            ("checkpoints", state.checkpoints),
            ("workspace_publishes", state.workspace_publishes),
        )
        if values
    ]
    if state.closure is not None:
        contaminated.append("closure")
    if contaminated:
        raise PromotionBundleError(
            "promotion session contains pre-run trajectory state: "
            + ", ".join(contaminated)
        )
    for experiment in state.experiments:
        if (
            experiment.status is not ExperimentStatus.REGISTERED
            or experiment.kind is not ExperimentKind.PROBE
            or experiment.extra.get("adapter_seed") is not True
            or experiment.hypothesis_ids
            or experiment.result is not None
            or experiment.source_run_id is not None
            or experiment.artifact_ids
            or experiment.evidence_fact_ids
            or experiment.evidence_run_ids
            or experiment.evidence_receipt_ids
            or experiment.evaluation_reason is not None
            or experiment.evaluated_at is not None
            or experiment.proof_recipe is not None
        ):
            raise PromotionBundleError(
                "promotion session contains a non-ingest pre-run experiment"
            )


def _knowledge_snapshot(
    store: StateStore,
    identity: ChallengeIdentity,
) -> tuple[int, str]:
    try:
        records = KnowledgeStore(store).list(identity)
    except (KnowledgeError, OSError) as error:
        raise PromotionBundleError(
            "promotion challenge knowledge could not be verified"
        ) from error
    snapshot = {
        "schema_version": 1,
        "documents": [record.to_dict() for record in records],
    }
    return len(records), _sha256(canonical_json_bytes(snapshot))


def require_promotion_knowledge_snapshot(
    store: StateStore,
    state: ChallengeState,
) -> None:
    """Re-attest the frozen empty knowledge surface at execution boundaries."""

    count, digest = _knowledge_snapshot(store, state.identity)
    expected_count = state.metadata.get(
        "evaluation_knowledge_document_count"
    )
    expected_digest = state.metadata.get(
        "evaluation_knowledge_snapshot_sha256"
    )
    if (
        count != 0
        or digest != _EMPTY_KNOWLEDGE_SNAPSHOT_SHA256
        or expected_count != 0
        or expected_digest != _EMPTY_KNOWLEDGE_SNAPSHOT_SHA256
    ):
        raise PromotionBundleError(
            "promotion challenge knowledge differs from the frozen empty "
            "snapshot"
        )


def _prepared_metadata(
    manifest: ParsedManifest,
    session: ManifestSession,
    frozen_at: str,
) -> dict[str, object]:
    return {
        "evaluation_case_id": session.case_id,
        "evaluation_attempt": session.attempt,
        "evaluation_system": session.arm,
        "evaluation_split": session.split,
        "evaluation_model": manifest.model_id,
        "evaluation_session_id": session.session_id,
        "evaluation_benchmark_id": manifest.benchmark_id,
        "evaluation_manifest_sha256": manifest.manifest_sha256,
        "evaluation_manifest_frozen_at": frozen_at,
        "evaluation_tool_manifest_sha256": (
            manifest.fingerprint.tool_manifest_sha256
        ),
        "evaluation_image_sha256": (
            manifest.fingerprint.image_sha256
        ),
        "evaluation_model_config_sha256": (
            manifest.fingerprint.model_config_sha256
        ),
        "evaluation_engine_source_sha256": (
            manifest.fingerprint.engine_source_sha256
        ),
        "evaluation_knowledge_document_count": 0,
        "evaluation_knowledge_snapshot_sha256": (
            _EMPTY_KNOWLEDGE_SNAPSHOT_SHA256
        ),
        "evaluation_prepared": True,
    }


def prepare_promotion_session(
    workspace_root: Path | str,
    frozen_manifest_path: Path | str,
    *,
    session_id: str,
) -> dict[str, object]:
    """Bind one still-unexecuted canonical state to its frozen session."""

    workspace = Path(workspace_root).resolve()
    manifest, frozen_at = _load_frozen_manifest(
        workspace,
        Path(frozen_manifest_path),
    )
    requested_id = _identifier(session_id, "session_id")
    session = manifest.sessions.get(requested_id)
    if session is None:
        raise PromotionBundleError(
            "session_id is not present in the frozen manifest"
        )
    actual_fingerprint = local_execution_fingerprint(workspace)
    if actual_fingerprint != manifest.fingerprint:
        raise PromotionBundleError(
            "current model/tool/image/source fingerprint does not match the "
            "frozen manifest"
        )
    config = load_config(workspace)
    configured_models = {
        getattr(config.models, field)
        for field in _MODEL_ROLE_FIELDS
    }
    if configured_models != {manifest.model_id}:
        raise PromotionBundleError(
            "all logical model roles must use the frozen single model"
        )

    store = StateStore(workspace)
    state = store.load(session.identity, recover=False)
    if (
        state.metadata.get("source_manifest_sha256")
        != session.input_manifest_sha256
    ):
        raise PromotionBundleError(
            "canonical state input manifest does not match the frozen case"
        )
    if (
        type(state.budget.allocated_seconds) is not int
        or state.budget.allocated_seconds
        != manifest.budget.wall_seconds
    ):
        raise PromotionBundleError(
            "canonical state does not have the frozen fixed wall budget"
        )
    if (
        state.budget.mode is not BudgetMode.BOUNDED
        or _timestamp_epoch(state.budget.deadline_utc) is None
    ):
        raise PromotionBundleError(
            "canonical state does not have a valid bounded wall deadline"
        )
    _require_clean_preexecution_context(state)
    knowledge_count, knowledge_sha256 = _knowledge_snapshot(
        store,
        session.identity,
    )
    if (
        knowledge_count != 0
        or knowledge_sha256 != _EMPTY_KNOWLEDGE_SNAPSHOT_SHA256
    ):
        raise PromotionBundleError(
            "promotion sessions require an empty challenge knowledge snapshot"
        )
    incoming_inventory = _incoming_inventory_summary(workspace, state)
    operator_input_sha256 = _operator_input_sha256(
        state,
        incoming_inventory,
    )
    initial_context_sha256 = _initial_context_sha256(state)
    executed_experiment = any(
        experiment.status is not ExperimentStatus.REGISTERED
        for experiment in state.experiments
    )
    if (
        state.runs
        or state.receipts
        or state.sessions
        or state.cycles
        or state.waves
        or state.candidates
        or state.submissions
        or executed_experiment
        or state.budget.spent_seconds != 0
    ):
        raise PromotionBundleError(
            "promotion session must be prepared before execution activity"
        )
    binding = _prepared_metadata(
        manifest,
        session,
        frozen_at,
    )
    binding["evaluation_initial_context_sha256"] = (
        initial_context_sha256
    )
    binding["evaluation_operator_input_schema_version"] = (
        _OPERATOR_INPUT_SCHEMA_VERSION
    )
    binding["evaluation_operator_input_sha256"] = operator_input_sha256
    if all(
        state.metadata.get(key) == expected
        for key, expected in binding.items()
    ):
        _require_evaluation_clock_binding(
            state,
            wall_seconds=manifest.budget.wall_seconds,
        )
        return {
            "schema_version": PROMOTION_BUNDLE_SCHEMA_VERSION,
            "prepared": True,
            "idempotent": True,
            "benchmark_id": manifest.benchmark_id,
            "manifest_sha256": manifest.manifest_sha256,
            "session_id": session.session_id,
            "case_id": session.case_id,
            "arm": session.arm,
            "attempt": session.attempt,
            "state_revision": state.revision,
            "evaluation_started_at": state.metadata[
                "evaluation_started_at"
            ],
            "evaluation_budget_deadline_utc": state.metadata[
                "evaluation_budget_deadline_utc"
            ],
            "automatic_challenge_start": False,
        }
    for key, expected in binding.items():
        observed = state.metadata.get(key)
        if observed is not None and observed != expected:
            raise PromotionBundleError(
                f"canonical state already has a conflicting {key}"
            )

    def apply(current: ChallengeState) -> None:
        started_at = _evaluation_utc_now()
        start_epoch = _timestamp_epoch(started_at)
        deadline = current.budget.deadline_utc
        deadline_epoch = _timestamp_epoch(deadline)
        if (
            current.budget.mode is not BudgetMode.BOUNDED
            or start_epoch is None
            or deadline_epoch is None
            or deadline_epoch <= start_epoch
            or _epoch_delta(deadline_epoch, start_epoch)
            > manifest.budget.wall_seconds
        ):
            raise PromotionBundleError(
                "canonical budget deadline must follow evaluation preparation "
                "within the frozen fixed wall budget"
            )
        for key, expected in binding.items():
            current.metadata[key] = expected
        current.metadata["evaluation_started_at"] = started_at
        current.metadata["evaluation_budget_deadline_utc"] = deadline
        current.metadata["human_intervention_count"] = 0
        current.metadata[
            "evaluation_human_interventions_finalized"
        ] = False
        current.metadata[
            "evaluation_secret_or_flag_leak_count"
        ] = 0
        current.metadata["evaluation_safety_finalized"] = False
        current.metadata["evaluation_finalized_at"] = None

    prepared = store.update(
        session.identity,
        apply,
        expected_revision=state.revision,
    )
    require_promotion_knowledge_snapshot(store, prepared)
    require_promotion_operator_input(workspace, prepared)
    return {
        "schema_version": PROMOTION_BUNDLE_SCHEMA_VERSION,
        "prepared": True,
        "idempotent": False,
        "benchmark_id": manifest.benchmark_id,
        "manifest_sha256": manifest.manifest_sha256,
        "session_id": session.session_id,
        "case_id": session.case_id,
        "arm": session.arm,
        "attempt": session.attempt,
        "state_revision": prepared.revision,
        "evaluation_started_at": prepared.metadata[
            "evaluation_started_at"
        ],
        "evaluation_budget_deadline_utc": prepared.metadata[
            "evaluation_budget_deadline_utc"
        ],
        "automatic_challenge_start": False,
    }


def finalize_promotion_session(
    workspace_root: Path | str,
    frozen_manifest_path: Path | str,
    *,
    session_id: str,
    human_interventions: int,
    secret_or_flag_leaks: int,
) -> dict[str, object]:
    """Finalize explicitly observable operator counters before capture."""

    human_count = _count(
        human_interventions,
        "human_interventions",
    )
    leak_count = _count(
        secret_or_flag_leaks,
        "secret_or_flag_leaks",
    )
    workspace = Path(workspace_root).resolve()
    manifest, frozen_at = _load_frozen_manifest(
        workspace,
        Path(frozen_manifest_path),
    )
    if local_execution_fingerprint(workspace) != manifest.fingerprint:
        raise PromotionBundleError(
            "current execution fingerprint differs from the frozen manifest"
        )
    requested_id = _identifier(session_id, "session_id")
    session = manifest.sessions.get(requested_id)
    if session is None:
        raise PromotionBundleError(
            "session_id is not present in the frozen manifest"
        )
    store = StateStore(workspace)
    state = store.load(session.identity, recover=False)
    binding = _prepared_metadata(manifest, session, frozen_at)
    if any(
        state.metadata.get(key) != expected
        for key, expected in binding.items()
    ):
        raise PromotionBundleError(
            "canonical state is not bound to this frozen session"
        )
    _sha256_value(
        state.metadata.get("evaluation_initial_context_sha256"),
        "evaluation_initial_context_sha256",
    )
    require_promotion_knowledge_snapshot(store, state)
    require_promotion_operator_input(workspace, state)
    start_epoch, deadline_epoch = _require_evaluation_clock_binding(
        state,
        wall_seconds=manifest.budget.wall_seconds,
    )
    if state.metadata.get(
        "evaluation_human_interventions_finalized"
    ) is True or state.metadata.get("evaluation_safety_finalized") is True:
        if (
            state.metadata.get("human_intervention_count")
            == human_count
            and state.metadata.get(
                "evaluation_secret_or_flag_leak_count"
            )
            == leak_count
            and state.metadata.get(
                "evaluation_human_interventions_finalized"
            )
            is True
            and state.metadata.get("evaluation_safety_finalized") is True
            and type(
                state.metadata.get("evaluation_finalized_at")
            )
            is str
        ):
            finalized_epoch = _timestamp_epoch(
                state.metadata["evaluation_finalized_at"]
            )
            if (
                finalized_epoch is None
                or finalized_epoch < start_epoch
                or finalized_epoch > deadline_epoch
                or _epoch_delta(finalized_epoch, start_epoch)
                > manifest.budget.wall_seconds
            ):
                raise PromotionBundleError(
                    "existing evaluation finalization is outside the frozen "
                    "fixed wall window"
                )
            _require_activity_window(
                state,
                start_epoch=start_epoch,
                finalized_epoch=finalized_epoch,
            )
            return {
                "schema_version": PROMOTION_BUNDLE_SCHEMA_VERSION,
                "finalized": True,
                "idempotent": True,
                "session_id": session.session_id,
                "state_revision": state.revision,
                "finalized_at": state.metadata[
                    "evaluation_finalized_at"
                ],
            }
        raise PromotionBundleError(
            "promotion session counters were already finalized"
        )

    def apply(current: ChallengeState) -> None:
        current_start, current_deadline = (
            _require_evaluation_clock_binding(
                current,
                wall_seconds=manifest.budget.wall_seconds,
            )
        )
        finalized_at = _evaluation_utc_now()
        finalized_epoch = _timestamp_epoch(finalized_at)
        if (
            finalized_epoch is None
            or finalized_epoch < current_start
            or finalized_epoch > current_deadline
            or _epoch_delta(finalized_epoch, current_start)
            > manifest.budget.wall_seconds
        ):
            raise PromotionBundleError(
                "evaluation finalization must remain inside the frozen fixed "
                "wall window"
            )
        _require_activity_window(
            current,
            start_epoch=current_start,
            finalized_epoch=finalized_epoch,
        )
        current.metadata["human_intervention_count"] = human_count
        current.metadata[
            "evaluation_human_interventions_finalized"
        ] = True
        current.metadata[
            "evaluation_secret_or_flag_leak_count"
        ] = leak_count
        current.metadata["evaluation_safety_finalized"] = True
        current.metadata["evaluation_finalized_at"] = finalized_at

    finalized = store.update(
        session.identity,
        apply,
        expected_revision=state.revision,
    )
    require_promotion_operator_input(workspace, finalized)
    return {
        "schema_version": PROMOTION_BUNDLE_SCHEMA_VERSION,
        "finalized": True,
        "idempotent": False,
        "session_id": session.session_id,
        "state_revision": finalized.revision,
        "human_interventions": human_count,
        "secret_or_flag_leaks": leak_count,
        "finalized_at": finalized.metadata["evaluation_finalized_at"],
    }


def _validate_relative_path(value: object, label: str) -> PurePosixPath:
    if (
        type(value) is not str
        or not value
        or "\\" in value
        or PureWindowsPath(value).is_absolute()
    ):
        raise PromotionBundleError(
            f"{label} must be a normalized relative POSIX path"
        )
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or relative.as_posix() != value
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise PromotionBundleError(
            f"{label} must be a normalized relative POSIX path"
        )
    return relative


def _assert_no_symlink_components(root: Path, relative: PurePosixPath) -> Path:
    current = root
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise PromotionBundleError(
                f"capture source is missing: {relative.as_posix()}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise PromotionBundleError(
                f"capture source traverses a symlink: {relative.as_posix()}"
            )
    try:
        resolved_root = root.resolve(strict=True)
        resolved = current.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as error:
        raise PromotionBundleError(
            f"capture source escapes its challenge: {relative.as_posix()}"
        ) from error
    return current


def _parse_state(
    payload: bytes,
    *,
    expected: ChallengeIdentity,
    label: str,
) -> ChallengeState:
    try:
        raw = strict_json_loads(payload, max_bytes=MAX_STATE_BYTES)
        if type(raw) is not dict:
            raise PromotionBundleError(f"{label} must contain an object")
        validate_state_protocol_shape(raw)
        state = ChallengeState.from_dict(upgrade_state(raw))
        state.validate()
    except PromotionBundleError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise PromotionBundleError(
            f"{label} is not a valid canonical state"
        ) from error
    if state.identity != expected:
        raise PromotionBundleError(
            f"{label} identity does not match the frozen session"
        )
    return state


def _state_relative_path(session: ManifestSession) -> PurePosixPath:
    return PurePosixPath(
        ".ctfos",
        "contests",
        session.contest_id,
        "challenges",
        session.category,
        session.challenge_id,
        "state.json",
    )


def _challenge_relative_path(
    session: ManifestSession,
) -> PurePosixPath:
    return _state_relative_path(session).parent


def _source_challenge_root(
    workspace: Path,
    session: ManifestSession,
) -> Path:
    return workspace.joinpath(*_challenge_relative_path(session).parts)


def _referenced_files(state: ChallengeState) -> tuple[PurePosixPath, ...]:
    values: set[str] = set()
    for artifact in state.artifacts:
        values.add(artifact.path)
    for run in state.runs:
        for value in (
            run.request_path,
            run.result_path,
            run.validation_path,
        ):
            if value is not None:
                values.add(value)
    return tuple(
        sorted(
            (
                _validate_relative_path(value, "state evidence path")
                for value in values
            ),
            key=lambda value: value.as_posix(),
        )
    )


def _write_capture_file(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    atomic_write_bytes(path, payload, mode=0o400)


def _metric_value(
    report: EvaluationReport,
    name: str,
) -> tuple[Mapping[str, object] | None, bool]:
    metric = report.metrics[name]
    if metric.status not in {"available", "partial"}:
        return None, False
    if not isinstance(metric.value, Mapping):
        return None, False
    return metric.value, metric.status == "available"


def _nonnegative_number(value: object) -> float | None:
    if type(value) is int:
        return float(value) if value >= 0 else None
    if type(value) is float:
        return value if math.isfinite(value) and value >= 0 else None
    return None


def _candidate_binding(candidate: object) -> _CandidateBinding | None:
    candidate_id = getattr(candidate, "id", None)
    value = getattr(candidate, "value", None)
    if type(candidate_id) is not str or type(value) is not str:
        return None
    return _CandidateBinding(
        candidate_id=candidate_id,
        value_sha256=_sha256(value.encode("utf-8")),
    )


def _redacted_accepted_submission_snapshot(
    *,
    state: ChallengeState,
    ledger_records: Sequence[Mapping[str, object]],
) -> tuple[dict[str, object], ...]:
    """Freeze accepted bindings without copying submitted candidate values."""

    snapshot: list[dict[str, object]] = []
    seen: set[str] = set()
    for record in ledger_records:
        if (
            record.get("contest_id") != state.contest_id
            or record.get("category") != state.category
            or record.get("challenge_id") != state.challenge_id
            or record.get("status") != SubmissionStatus.ACCEPTED.value
        ):
            continue
        submission_id = _identifier(
            record.get("id"),
            "accepted submission id",
        )
        if submission_id in seen:
            raise PromotionBundleError(
                "accepted submission ledger ids must be unique"
            )
        seen.add(submission_id)
        candidate_id = _identifier(
            record.get("candidate_id"),
            "accepted submission candidate_id",
        )
        flag = record.get("flag")
        if type(flag) is not str:
            raise PromotionBundleError(
                "accepted submission ledger flag must be a string"
            )
        recorded_at = _parse_timestamp(
            record.get("recorded_at"),
            "accepted submission recorded_at",
        )
        snapshot.append(
            {
                "submission_id": submission_id,
                "candidate_id": candidate_id,
                "value_sha256": _sha256(flag.encode("utf-8")),
                "status": SubmissionStatus.ACCEPTED.value,
                "recorded_at": recorded_at,
            }
        )
    return tuple(
        sorted(snapshot, key=lambda item: str(item["submission_id"]))
    )


def _parse_accepted_submission_snapshot(
    value: object,
) -> tuple[dict[str, object], ...]:
    raw_records = _strict_list(
        value,
        label="accepted submission snapshot",
        maximum=4096,
    )
    parsed: list[dict[str, object]] = []
    seen: set[str] = set()
    for value_record in raw_records:
        record = _strict_mapping(
            value_record,
            keys=frozenset(
                {
                    "submission_id",
                    "candidate_id",
                    "value_sha256",
                    "status",
                    "recorded_at",
                }
            ),
            label="accepted submission snapshot record",
        )
        submission_id = _identifier(
            record["submission_id"],
            "accepted submission snapshot submission_id",
        )
        if submission_id in seen:
            raise PromotionBundleError(
                "accepted submission snapshot ids must be unique"
            )
        seen.add(submission_id)
        status = record["status"]
        if status != SubmissionStatus.ACCEPTED.value:
            raise PromotionBundleError(
                "accepted submission snapshot status must be accepted"
            )
        parsed.append(
            {
                "submission_id": submission_id,
                "candidate_id": _identifier(
                    record["candidate_id"],
                    "accepted submission snapshot candidate_id",
                ),
                "value_sha256": _sha256_value(
                    record["value_sha256"],
                    "accepted submission snapshot value_sha256",
                ),
                "status": status,
                "recorded_at": _parse_timestamp(
                    record["recorded_at"],
                    "accepted submission snapshot recorded_at",
                ),
            }
        )
    ordered = sorted(parsed, key=lambda item: str(item["submission_id"]))
    if parsed != ordered:
        raise PromotionBundleError(
            "accepted submission snapshot must be sorted by submission_id"
        )
    return tuple(parsed)


def _accepted_submission_bindings(
    *,
    state: ChallengeState,
    ledger_records: Sequence[Mapping[str, object]],
) -> tuple[
    frozenset[str],
    frozenset[_CandidateBinding],
    bool,
]:
    """Bind accepted state records to the frozen redacted submission values."""

    accepted_submissions = tuple(
        submission
        for submission in state.submissions
        if submission.status is SubmissionStatus.ACCEPTED
    )
    accepted_ids = frozenset(
        submission.candidate_id
        for submission in accepted_submissions
    )
    candidate_bindings = {
        candidate.id: _candidate_binding(candidate)
        for candidate in state.candidates
    }
    ledger_by_id: dict[str, Mapping[str, object]] = {}
    ledger_accepted_ids: set[str] = set()
    valid = True
    for record in ledger_records:
        record_id = record.get("submission_id")
        if type(record_id) is not str or not record_id:
            valid = False
            continue
        if record_id in ledger_by_id:
            valid = False
            continue
        ledger_by_id[record_id] = record
        if record.get("status") == SubmissionStatus.ACCEPTED.value:
            ledger_accepted_ids.add(record_id)

    bindings: set[_CandidateBinding] = set()
    state_accepted_record_ids: set[str] = set()
    for submission in accepted_submissions:
        state_accepted_record_ids.add(submission.id)
        record = ledger_by_id.get(submission.id)
        candidate = candidate_bindings.get(submission.candidate_id)
        value_sha256 = (
            record.get("value_sha256") if record is not None else None
        )
        if (
            record is None
            or candidate is None
            or record.get("candidate_id") != submission.candidate_id
            or record.get("status") != SubmissionStatus.ACCEPTED.value
            or record.get("recorded_at") != submission.submitted_at
            or type(value_sha256) is not str
            or _SHA256_RE.fullmatch(value_sha256) is None
        ):
            valid = False
            continue
        ledger_binding = _CandidateBinding(
            candidate_id=submission.candidate_id,
            value_sha256=value_sha256,
        )
        if ledger_binding != candidate:
            valid = False
            continue
        bindings.add(ledger_binding)

    if ledger_accepted_ids != state_accepted_record_ids:
        valid = False
    if accepted_ids and len(bindings) != len(accepted_ids):
        valid = False
    return accepted_ids, frozenset(bindings), valid


def _canonical_candidate_proof_evidence(
    *,
    state: ChallengeState,
    challenge_root: Path,
) -> tuple[tuple[_CandidateProofEvidence, ...], bool]:
    """Re-read canonical proof evidence while retaining candidate identity.

    The public evaluator intentionally exposes bounded aggregates. Promotion
    additionally needs the identity that those aggregates omit so an accepted
    candidate cannot borrow another candidate's proof. Reuse the evaluator's
    exact semantic parsers here; only candidate IDs and value digests cross
    this boundary.
    """

    candidates = {
        candidate.id: candidate for candidate in state.candidates
    }
    record = canonical_evaluation._LoadedState(  # noqa: SLF001
        state=state,
        root=challenge_root,
    )
    observations: list[_CandidateProofEvidence] = []
    proof_run_binding_invalid = False

    runs = {run.id: run for run in state.runs}

    def append(
        observation: object,
        run_ids: object,
        *,
        require_direct_candidate_id: bool = False,
    ) -> None:
        nonlocal proof_run_binding_invalid
        candidate_id = getattr(observation, "candidate_id", None)
        candidate = candidates.get(candidate_id)
        binding = _candidate_binding(candidate)
        passed = getattr(observation, "passed", None)
        successful_attempts = getattr(
            observation,
            "successful_attempts",
            None,
        )
        total_attempts = getattr(
            observation,
            "total_attempts",
            None,
        )
        completed_at = getattr(observation, "completed_at", None)
        if (
            binding is None
            or type(passed) is not bool
            or type(successful_attempts) is not int
            or successful_attempts < 0
            or type(total_attempts) is not int
            or total_attempts < 0
            or successful_attempts > total_attempts
            or type(completed_at) is not str
            or type(run_ids) not in {list, tuple}
            or len(run_ids) != total_attempts
            or not all(type(run_id) is str and run_id for run_id in run_ids)
            or len(set(run_ids)) != len(run_ids)
        ):
            return
        exact_run_ids = tuple(run_ids)
        completed_epoch = _timestamp_epoch(completed_at)
        run_epochs = [
            _timestamp_epoch(runs[run_id].created_at)
            for run_id in exact_run_ids
            if run_id in runs
        ]
        if (
            candidate is None
            or not set(exact_run_ids) <= set(candidate.proof_run_ids)
            or any(
                run_id not in runs
                or runs[run_id].origin is not RunOrigin.PROOF
                or runs[run_id].status not in _TERMINAL_RUN_STATUSES
                or (
                    require_direct_candidate_id
                    and runs[run_id].extra.get("candidate_id")
                    != candidate_id
                )
                for run_id in exact_run_ids
            )
            or completed_epoch is None
            or len(run_epochs) != len(exact_run_ids)
            or any(run_epoch is None for run_epoch in run_epochs)
            or any(
                float(run_epoch) > completed_epoch
                for run_epoch in run_epochs
                if run_epoch is not None
            )
        ):
            proof_run_binding_invalid = True
            return
        observations.append(
            _CandidateProofEvidence(
                binding=binding,
                passed=passed,
                successful_attempts=successful_attempts,
                total_attempts=total_attempts,
                completed_at=completed_at,
                run_ids=exact_run_ids,
            )
        )

    for artifact in state.artifacts:
        candidate_id = canonical_evaluation._proof_path_candidate(  # noqa: SLF001
            artifact.path
        )
        if candidate_id is None or candidate_id not in candidates:
            continue
        try:
            observation = canonical_evaluation._parse_proof_result(  # noqa: SLF001
                record,
                artifact.id,
                candidate_id,
            )
            raw = canonical_evaluation._strict_json_bytes(  # noqa: SLF001
                canonical_evaluation._read_verified_artifact(  # noqa: SLF001
                    challenge_root,
                    artifact,
                    maximum_bytes=(
                        canonical_evaluation.MAX_PROOF_RESULT_BYTES
                    ),
                ),
                "proof result artifact",
            )
        except (canonical_evaluation.EvaluationInputError, OSError):
            continue
        if (
            type(raw) is not dict
            or raw.get("source_manifest_sha256")
            != state.metadata.get("source_manifest_sha256")
        ):
            continue
        append(
            observation,
            raw.get("run_ids"),
            require_direct_candidate_id=True,
        )

    for candidate in state.candidates:
        if "crypto_metamorphic_proof" not in candidate.extra:
            continue
        try:
            observation = (
                canonical_evaluation._parse_crypto_metamorphic_result(  # noqa: SLF001
                    record,
                    candidate.id,
                )
            )
        except (canonical_evaluation.EvaluationInputError, OSError):
            continue
        binding = candidate.extra["crypto_metamorphic_proof"]
        append(observation, binding["proof_result"]["run_ids"])

    for experiment in state.experiments:
        result = experiment.result
        if (
            type(result) is not dict
            or "rev_proof_evidence" not in result
        ):
            continue
        try:
            observation = canonical_evaluation._parse_rev_stdin_result(  # noqa: SLF001
                record,
                experiment,
            )
        except (canonical_evaluation.EvaluationInputError, OSError):
            continue
        append(observation, result["proof_result"]["run_ids"])

    return tuple(observations), proof_run_binding_invalid


def _bound_first_valid_result_seconds(
    *,
    state: ChallengeState,
    accepted_bindings: frozenset[_CandidateBinding],
    evidence: Sequence[_CandidateProofEvidence],
    start_epoch: float | None,
    finalized_epoch: float | None,
) -> float | None:
    candidate_bindings = {
        candidate.id: _candidate_binding(candidate)
        for candidate in state.candidates
    }
    if start_epoch is None or finalized_epoch is None:
        return None
    accepted_timestamps: dict[_CandidateBinding, list[float]] = {
        binding: [] for binding in accepted_bindings
    }
    proof_timestamps: dict[_CandidateBinding, list[float]] = {
        binding: [] for binding in accepted_bindings
    }
    for submission in state.submissions:
        if submission.status is not SubmissionStatus.ACCEPTED:
            continue
        binding = candidate_bindings.get(submission.candidate_id)
        if binding not in accepted_bindings:
            continue
        timestamp = _timestamp_epoch(submission.submitted_at)
        if (
            timestamp is not None
            and start_epoch < timestamp <= finalized_epoch
        ):
            accepted_timestamps[binding].append(timestamp)
    for observation in evidence:
        if (
            observation.binding not in accepted_bindings
            or not observation.passed
            or observation.successful_attempts <= 0
            or observation.total_attempts <= 0
        ):
            continue
        timestamp = _timestamp_epoch(observation.completed_at)
        if (
            timestamp is not None
            and start_epoch < timestamp <= finalized_epoch
        ):
            proof_timestamps[observation.binding].append(timestamp)
    binding_valid_timestamps = [
        max(
            min(accepted_timestamps[binding]),
            min(proof_timestamps[binding]),
        )
        for binding in accepted_bindings
        if (
            accepted_timestamps[binding]
            and proof_timestamps[binding]
        )
    ]
    if not binding_valid_timestamps:
        return None
    return _epoch_delta(min(binding_valid_timestamps), start_epoch)


def _bound_run_file(
    *,
    challenge_root: Path,
    run: RunReference,
    pointer_field: str,
    digest_field: str,
) -> bytes:
    pointer = getattr(run, pointer_field)
    expected_digest = run.extra.get(digest_field)
    if (
        type(pointer) is not str
        or type(expected_digest) is not str
        or _SHA256_RE.fullmatch(expected_digest) is None
    ):
        raise PromotionBundleError(
            f"model run {run.id} lacks an exact {pointer_field} binding"
        )
    relative = _validate_relative_path(
        pointer,
        f"model run {run.id} {pointer_field}",
    )
    path = _assert_no_symlink_components(challenge_root, relative)
    payload = _read_regular(
        path,
        maximum=MAX_CAPTURE_FILE_BYTES,
        label=f"model run {run.id} {pointer_field}",
    )
    if _sha256(payload) != expected_digest:
        raise PromotionBundleError(
            f"model run {run.id} {pointer_field} hash mismatch"
        )
    return payload


def _strict_json_payload(
    payload: bytes,
    *,
    label: str,
) -> Mapping[str, object]:
    try:
        value = strict_json_loads(
            payload,
            max_bytes=MAX_CAPTURE_FILE_BYTES,
        )
    except (UnicodeError, ValueError) as error:
        raise PromotionBundleError(
            f"{label} is not strict JSON"
        ) from error
    if type(value) is not dict:
        raise PromotionBundleError(f"{label} must be an exact object")
    return value


def _usage_record(value: object) -> dict[str, int] | None:
    if type(value) is not dict or set(value) != {
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "reasoning_output_tokens",
    }:
        return None
    if any(
        type(value.get(field)) is not int or value[field] < 0
        for field in value
    ):
        return None
    return {
        field: value[field]
        for field in (
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "reasoning_output_tokens",
        )
    }


def _artifact_payload(
    *,
    challenge_root: Path,
    artifact: object,
) -> bytes:
    path_value = getattr(artifact, "path", None)
    digest = getattr(artifact, "sha256", None)
    size = getattr(artifact, "size", None)
    artifact_id = getattr(artifact, "id", "<unknown>")
    if (
        type(path_value) is not str
        or type(digest) is not str
        or _SHA256_RE.fullmatch(digest) is None
        or type(size) is not int
        or size < 0
    ):
        raise PromotionBundleError(
            f"thin evidence artifact {artifact_id} is not exactly bound"
        )
    relative = _validate_relative_path(
        path_value,
        f"thin evidence artifact {artifact_id}",
    )
    path = _assert_no_symlink_components(challenge_root, relative)
    payload = _read_regular(
        path,
        maximum=MAX_CAPTURE_FILE_BYTES,
        label=f"thin evidence artifact {artifact_id}",
    )
    if len(payload) != size or _sha256(payload) != digest:
        raise PromotionBundleError(
            f"thin evidence artifact {artifact_id} hash mismatch"
        )
    return payload


def _thin_attestation(
    *,
    state: ChallengeState,
    run: RunReference,
    challenge_root: Path,
    command_contract_sha256: str,
    launch_binding_sha256: str,
) -> tuple[int, dict[str, int]]:
    request_payload = _bound_run_file(
        challenge_root=challenge_root,
        run=run,
        pointer_field="request_path",
        digest_field="request_sha256",
    )
    result_payload = _bound_run_file(
        challenge_root=challenge_root,
        run=run,
        pointer_field="result_path",
        digest_field="result_sha256",
    )
    validation_payload = _bound_run_file(
        challenge_root=challenge_root,
        run=run,
        pointer_field="validation_path",
        digest_field="validation_sha256",
    )
    request = _strict_json_payload(
        request_payload,
        label=f"thin run {run.id} request",
    )
    result = _strict_json_payload(
        result_payload,
        label=f"thin run {run.id} result",
    )
    validation = _strict_json_payload(
        validation_payload,
        label=f"thin run {run.id} validation",
    )
    if (
        request.get("run_id") != run.id
        or request.get("base_revision") != run.base_revision
        or request.get("evaluation_scaffold") != THIN_SCAFFOLD
        or request.get("execution_transport") != "headless_jsonl"
        or request.get("usage_attestation")
        != "codex_jsonl_events"
        or request.get("command_contract_sha256")
        != command_contract_sha256
    ):
        raise PromotionBundleError(
            f"thin run {run.id} request contract is invalid"
        )
    expected_result_keys = {
        "schema_version",
        "base_revision",
        "status",
        "evaluation_scaffold",
        "semantic_output_committed",
        "usage",
        "usage_event_observed",
        "capture_complete",
        "thread_id_sha256",
        "evidence",
        "automatic_submission",
    }
    expected_validation_keys = {
        "schema_version",
        "base_revision",
        "ok",
        "errors",
    }
    usage = _usage_record(result.get("usage"))
    if (
        set(result) != expected_result_keys
        or result.get("schema_version") != 1
        or result.get("base_revision") != run.base_revision
        or result.get("status") != run.status.value
        or result.get("evaluation_scaffold") != THIN_SCAFFOLD
        or result.get("semantic_output_committed") is not False
        or result.get("usage_event_observed") is not True
        or result.get("capture_complete") is not True
        or result.get("automatic_submission") is not False
        or usage is None
        or set(validation) != expected_validation_keys
        or validation.get("schema_version") != 1
        or validation.get("base_revision") != run.base_revision
        or validation.get("ok") is not True
        or validation.get("errors") != []
    ):
        raise PromotionBundleError(
            f"thin run {run.id} result attestation is invalid"
        )
    if (
        usage != _usage_record(run.extra.get("usage"))
        or result.get("thread_id_sha256")
        != run.extra.get("produced_thread_id_sha256")
    ):
        raise PromotionBundleError(
            f"thin run {run.id} result/state attestation differs"
        )
    attempt_count = run.extra.get("attempt_count")
    evidence_ids = run.extra.get("evidence_artifact_ids")
    if (
        type(attempt_count) is not int
        or attempt_count < 1
        or type(evidence_ids) is not list
        or len(evidence_ids) != 1 + (4 * attempt_count)
        or len(set(evidence_ids)) != len(evidence_ids)
        or any(type(item) is not str for item in evidence_ids)
        or run.extra.get("capture_complete") is not True
        or run.extra.get("launch_binding_sha256")
        != launch_binding_sha256
    ):
        raise PromotionBundleError(
            f"thin run {run.id} evidence inventory is invalid"
        )
    artifacts = {artifact.id: artifact for artifact in state.artifacts}
    if any(
        artifact_id not in artifacts
        or artifacts[artifact_id].source_run_id != run.id
        for artifact_id in evidence_ids
    ):
        raise PromotionBundleError(
            f"thin run {run.id} evidence references are invalid"
        )
    run_root = PurePosixPath(run.request_path).parent
    expected_paths: list[tuple[PurePosixPath, str]] = [
        (
            run_root / "output-schema.json",
            "application/schema+json",
        )
    ]
    for ordinal in range(1, attempt_count + 1):
        expected_paths.extend(
            (
                (
                    run_root / "raw" / f"attempt-{ordinal}.jsonl",
                    "application/x-ndjson",
                ),
                (
                    run_root / "raw" / f"attempt-{ordinal}.stderr",
                    "text/plain",
                ),
                (
                    run_root / f"attempt-{ordinal}-output.json",
                    "application/json",
                ),
                (
                    run_root
                    / "raw"
                    / f"attempt-{ordinal}-capture.json",
                    "application/json",
                ),
            )
        )
    ordered_artifacts = [artifacts[item] for item in evidence_ids]
    if [
        (PurePosixPath(item.path), item.media_type)
        for item in ordered_artifacts
    ] != expected_paths:
        raise PromotionBundleError(
            f"thin run {run.id} evidence paths are not exact"
        )
    payloads = [
        _artifact_payload(
            challenge_root=challenge_root,
            artifact=artifact,
        )
        for artifact in ordered_artifacts
    ]
    evidence_rows = [
        {
            "artifact_id": artifact.id,
            "path": artifact.path,
            "sha256": artifact.sha256,
            "size_bytes": artifact.size,
        }
        for artifact in ordered_artifacts
    ]
    if result.get("evidence") != evidence_rows:
        raise PromotionBundleError(
            f"thin run {run.id} result evidence inventory differs"
        )

    accumulated_usage = {
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_output_tokens": 0,
    }
    final_thread_id: str | None = None
    usage_event_observed = False
    cumulative_events = 0
    for index in range(attempt_count):
        base = 1 + (4 * index)
        jsonl_payload = payloads[base]
        stderr_payload = payloads[base + 1]
        capture = _strict_json_payload(
            payloads[base + 3],
            label=f"thin run {run.id} capture {index + 1}",
        )
        try:
            text = jsonl_payload.decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise PromotionBundleError(
                f"thin run {run.id} JSONL is not UTF-8"
            ) from error
        attempt_events = 0
        for raw_line in text.splitlines():
            if not raw_line:
                continue
            try:
                event = strict_json_loads(
                    raw_line.encode("utf-8"),
                    max_bytes=MAX_CAPTURE_FILE_BYTES,
                )
            except (UnicodeError, ValueError) as error:
                raise PromotionBundleError(
                    f"thin run {run.id} JSONL is malformed"
                ) from error
            if type(event) is not dict:
                raise PromotionBundleError(
                    f"thin run {run.id} JSONL event is not an object"
                )
            attempt_events += 1
            event_type = event.get("type", event.get("event_type"))
            if event_type == "thread.started":
                possible_id = event.get(
                    "thread_id",
                    event.get("thread", event.get("id")),
                )
                if type(possible_id) is dict:
                    possible_id = possible_id.get("id")
                if valid_thread_id(possible_id):
                    final_thread_id = possible_id
            event_usage = event.get("usage")
            if type(event_usage) is dict:
                for field in accumulated_usage:
                    token = event_usage.get(field, 0)
                    if type(token) is int and token >= 0:
                        accumulated_usage[field] += token
                if event_type == "turn.completed":
                    usage_event_observed = True
        cumulative_events += attempt_events
        stdout_capture = capture.get("stdout_jsonl")
        stderr_capture = capture.get("stderr")
        structured_output = capture.get("structured_output")
        accumulator = capture.get("event_accumulator")
        if (
            capture.get("schema_version") != 1
            or type(stdout_capture) is not dict
            or stdout_capture.get("stored_bytes") != len(jsonl_payload)
            or stdout_capture.get("bytes") != len(jsonl_payload)
            or stdout_capture.get("truncated") is not False
            or stdout_capture.get("truncation_known") is not True
            or stdout_capture.get("capture_complete") is not True
            or stdout_capture.get("oversized_event_lines") != 0
            or type(stderr_capture) is not dict
            or stderr_capture.get("stored_bytes") != len(stderr_payload)
            or type(stderr_capture.get("bytes")) is not int
            or stderr_capture["bytes"] < len(stderr_payload)
            or stderr_capture.get("truncation_known") is not True
            or stderr_capture.get("truncated")
            is not (
                stderr_capture["bytes"] > len(stderr_payload)
            )
            or stderr_capture.get("capture_complete") is not True
            or type(structured_output) is not dict
            or structured_output.get("bytes") != len(payloads[base + 2])
            or type(accumulator) is not dict
            or type(accumulator.get("event_limit")) is not int
            or accumulator["event_limit"] < 0
            or accumulator.get("events_stored")
            != min(cumulative_events, accumulator["event_limit"])
            or accumulator.get("events_dropped")
            != max(0, cumulative_events - accumulator["event_limit"])
            or accumulator.get("malformed_lines_stored") != 0
            or accumulator.get("malformed_lines_dropped") != 0
        ):
            raise PromotionBundleError(
                f"thin run {run.id} capture metadata is invalid"
            )
    thread_digest = (
        _sha256(final_thread_id.encode("utf-8"))
        if final_thread_id is not None
        else None
    )
    if (
        not usage_event_observed
        or accumulated_usage != usage
        or usage["input_tokens"] + usage["output_tokens"] <= 0
        or thread_digest != result.get("thread_id_sha256")
    ):
        raise PromotionBundleError(
            f"thin run {run.id} JSONL usage attestation differs"
        )
    return attempt_count, usage


def _managed_model_call_count(
    *,
    run: RunReference,
    challenge_root: Path,
) -> int:
    _bound_run_file(
        challenge_root=challenge_root,
        run=run,
        pointer_field="request_path",
        digest_field="request_sha256",
    )
    result = _strict_json_payload(
        _bound_run_file(
            challenge_root=challenge_root,
            run=run,
            pointer_field="result_path",
            digest_field="result_sha256",
        ),
        label=f"managed run {run.id} result",
    )
    _strict_json_payload(
        _bound_run_file(
            challenge_root=challenge_root,
            run=run,
            pointer_field="validation_path",
            digest_field="validation_sha256",
        ),
        label=f"managed run {run.id} validation",
    )
    attempt_count = run.extra.get("attempt_count")
    if (
        type(attempt_count) is not int
        or attempt_count < 0
        or result.get("attempt_count") != attempt_count
        or result.get("status") != run.status.value
    ):
        raise PromotionBundleError(
            f"managed run {run.id} call count attestation is invalid"
        )
    return attempt_count


def _scaffold_collection_blockers(
    *,
    session: ManifestSession,
    manifest: ParsedManifest,
    state: ChallengeState,
    config: EngineConfig,
    model_runs: Sequence[RunReference],
    challenge_root: Path,
) -> tuple[tuple[str, ...], int]:
    blockers: list[str] = []
    model_call_count = 0
    raw_launch = state.metadata.get(SCAFFOLD_LAUNCH_METADATA_KEY)
    if raw_launch is None:
        return ("scaffold_launch_missing",), 0
    try:
        binding, _launched_at = parse_scaffold_launch_record(raw_launch)
    except ScaffoldBindingError:
        return ("scaffold_launch_invalid",), 0
    expected_static = {
        "arm": session.arm,
        "benchmark_id": manifest.benchmark_id,
        "case_id": session.case_id,
        "contest_id": session.contest_id,
        "category": session.category,
        "challenge_id": session.challenge_id,
        "session_id": session.session_id,
        "manifest_sha256": manifest.manifest_sha256,
        "source_manifest_sha256": session.input_manifest_sha256,
        "configuration_epoch": state.configuration_epoch,
        "model_id": manifest.model_id,
        "runtime_image_digest": (
            "sha256:" + manifest.fingerprint.image_sha256
        ),
        "tool_manifest_sha256": (
            manifest.fingerprint.tool_manifest_sha256
        ),
        "model_config_sha256": (
            manifest.fingerprint.model_config_sha256
        ),
        "engine_source_sha256": (
            manifest.fingerprint.engine_source_sha256
        ),
    }
    observed_static = {
        key: getattr(binding, key) for key in expected_static
    }
    if observed_static != expected_static:
        blockers.append("scaffold_launch_binding_mismatch")

    typed_model_runs = list(model_runs)
    if session.arm == THIN_SCAFFOLD:
        thin_session = LiveSession(
            session_key="promotion-thin-contract",
            working_directory=Path("/challenge"),
            prompt="frozen thin evaluation",
            model_id=manifest.model_id,
            reasoning_effort=ReasoningEffort(
                config.models.captain_effort
            ),
            logical_worker_roles=(),
            scaffold=LIVE_THIN_SCAFFOLD,
        )
        expected_contract = LiveCommandBuilder(
            models=ModelCatalog(
                sol=manifest.model_id,
                terra=manifest.model_id,
                luna=manifest.model_id,
            )
        ).command_contract_sha256(
            thin_session,
            headless=True,
        )
        if binding.command_contract_sha256 != expected_contract:
            blockers.append("thin_command_contract_mismatch")
        if state.sessions or state.cycles or state.waves:
            blockers.append("thin_contains_managed_orchestration")
        if len(typed_model_runs) != 1:
            blockers.append("thin_model_invocation_count_mismatch")
        for run in typed_model_runs:
            extra = run.extra
            if (
                run.origin is not RunOrigin.ASSISTED_MODEL
                or run.session_id != session.session_id
                or run.configuration_epoch != state.configuration_epoch
                or run.role != "captain"
                or extra.get("evaluation_scaffold") != THIN_SCAFFOLD
                or extra.get("execution_transport") != "headless_jsonl"
                or extra.get("usage_attestation")
                != "codex_jsonl_events"
                or extra.get("usage_attestation_valid") is not True
                or extra.get("semantic_output_committed") is not False
                or extra.get("logical_model_count") != 1
                or extra.get("logical_worker_roles") != []
                or extra.get("command_contract_sha256")
                != binding.command_contract_sha256
                or extra.get("launch_binding_sha256")
                != binding.binding_sha256
                or run.request_path is None
                or run.result_path is None
                or run.validation_path is None
            ):
                blockers.append("thin_usage_attestation_invalid")
                break
        if len(typed_model_runs) == 1:
            try:
                model_call_count, _usage = _thin_attestation(
                    state=state,
                    run=typed_model_runs[0],
                    challenge_root=challenge_root,
                    command_contract_sha256=(
                        binding.command_contract_sha256
                    ),
                    launch_binding_sha256=binding.binding_sha256,
                )
            except PromotionBundleError:
                blockers.append("thin_evidence_replay_invalid")
    elif session.arm == CTF_OS_SYSTEM:
        managed_sessions = [
            item
            for item in state.sessions
            if item.mode is SessionMode.MANAGED
        ]
        if len(managed_sessions) != 1 or len(state.sessions) != 1:
            blockers.append("managed_session_count_mismatch")
            return tuple(dict.fromkeys(blockers)), 0
        managed_session = managed_sessions[0]
        continuity = managed_session.extra.get(
            THREAD_CONTINUITY_SESSION_KEY
        )
        policy = (
            continuity.get("policy")
            if isinstance(continuity, Mapping)
            else None
        )
        if type(policy) is not str:
            blockers.append("managed_continuity_policy_missing")
        else:
            expected_models = {
                role: getattr(config.models, role)
                for role in _MODEL_ROLE_FIELDS
            }
            if (
                not isinstance(continuity, Mapping)
                or continuity.get("configuration_epoch")
                != state.configuration_epoch
                or continuity.get("runtime_image_digest")
                != config.runtime.image_digest
                or continuity.get("captain_effort")
                != config.models.captain_effort
                or continuity.get("worker_effort")
                != config.models.worker_effort
                or continuity.get("models") != expected_models
            ):
                blockers.append(
                    "managed_continuity_configuration_mismatch"
                )
            try:
                expected_contract = managed_command_contract_sha256(
                    model_id=manifest.model_id,
                    captain_effort=config.models.captain_effort,
                    worker_effort=config.models.worker_effort,
                    thread_continuity_policy=policy,
                )
            except ScaffoldBindingError:
                blockers.append("managed_command_contract_invalid")
            else:
                if binding.command_contract_sha256 != expected_contract:
                    blockers.append("managed_command_contract_mismatch")
        managed_cycles = [
            cycle
            for cycle in state.cycles
            if cycle.session_id == managed_session.id
        ]
        if (
            not managed_cycles
            or len(managed_cycles) != len(state.cycles)
        ):
            blockers.append("managed_cycle_missing")
        managed_cycle_ids = {cycle.id for cycle in managed_cycles}
        captain_run_ids = {
            cycle.captain_run_id
            for cycle in managed_cycles
            if cycle.captain_run_id is not None
        }
        if any(
            run.origin is not RunOrigin.MANAGED_MODEL
            or run.session_id != managed_session.id
            or run.configuration_epoch != state.configuration_epoch
            or run.id not in managed_session.run_ids
            or run.cycle_id not in managed_cycle_ids
            for run in typed_model_runs
        ):
            blockers.append("managed_model_run_binding_mismatch")
        if not any(
            run.role == "captain"
            and run.id in captain_run_ids
            for run in typed_model_runs
        ):
            blockers.append("managed_captain_cycle_missing")
        if any(
            wave.session_id != managed_session.id
            or wave.cycle_id not in managed_cycle_ids
            for wave in state.waves
        ):
            blockers.append("managed_wave_binding_mismatch")
        try:
            model_call_count = sum(
                _managed_model_call_count(
                    run=run,
                    challenge_root=challenge_root,
                )
                for run in typed_model_runs
            )
        except PromotionBundleError:
            blockers.append("managed_model_evidence_replay_invalid")
    else:
        blockers.append("unsupported_scaffold_arm")
    return tuple(dict.fromkeys(blockers)), model_call_count


def _derive_attempt(
    *,
    session: ManifestSession,
    manifest: ParsedManifest,
    frozen_at: str,
    state: ChallengeState,
    report: EvaluationReport,
    config: EngineConfig,
    challenge_root: Path,
    submission_ledger: Sequence[Mapping[str, object]],
) -> tuple[PromotionAttempt, SafetyTotals, tuple[str, ...]]:
    blockers: list[str] = []
    if not report.complete or report.evaluated_states != 1:
        blockers.append("canonical_evaluation_incomplete")
    if (
        state.metadata.get("source_manifest_sha256")
        != session.input_manifest_sha256
    ):
        blockers.append("input_manifest_binding_mismatch")
    allocated = state.budget.allocated_seconds
    if (
        type(allocated) is not int
        or allocated != manifest.budget.wall_seconds
    ):
        blockers.append("fixed_wall_budget_mismatch")

    expected_metadata = _prepared_metadata(
        manifest,
        session,
        frozen_at,
    )
    for key, expected in expected_metadata.items():
        observed = state.metadata.get(key)
        if observed != expected:
            blockers.append(f"state_metadata_mismatch:{key}")
    initial_context_sha256 = state.metadata.get(
        "evaluation_initial_context_sha256"
    )
    if (
        type(initial_context_sha256) is not str
        or _SHA256_RE.fullmatch(initial_context_sha256) is None
    ):
        blockers.append("initial_context_binding_invalid")
    operator_input_sha256 = state.metadata.get(
        "evaluation_operator_input_sha256"
    )
    if (
        state.metadata.get(
            "evaluation_operator_input_schema_version"
        )
        != _OPERATOR_INPUT_SCHEMA_VERSION
        or type(operator_input_sha256) is not str
        or _SHA256_RE.fullmatch(operator_input_sha256) is None
    ):
        blockers.append("operator_input_binding_invalid")
    if (
        state.metadata.get(
            "evaluation_human_interventions_finalized"
        )
        is not True
    ):
        blockers.append("human_interventions_not_finalized")
    if state.metadata.get("evaluation_safety_finalized") is not True:
        blockers.append("safety_counters_not_finalized")
    start_epoch = _timestamp_epoch(
        state.metadata.get("evaluation_started_at")
    )
    bound_deadline = state.metadata.get(
        "evaluation_budget_deadline_utc"
    )
    deadline_epoch = _timestamp_epoch(bound_deadline)
    finalized_epoch = _timestamp_epoch(
        state.metadata.get("evaluation_finalized_at")
    )
    if start_epoch is None:
        blockers.append("evaluation_start_timestamp_invalid")
    if deadline_epoch is None:
        blockers.append("evaluation_budget_deadline_invalid")
    if state.budget.deadline_utc != bound_deadline:
        blockers.append("evaluation_budget_deadline_mismatch")
    if (
        start_epoch is not None
        and deadline_epoch is not None
        and (
            deadline_epoch <= start_epoch
            or _epoch_delta(deadline_epoch, start_epoch)
            > manifest.budget.wall_seconds
        )
    ):
        blockers.append("evaluation_start_outside_fixed_budget")
    if finalized_epoch is None:
        blockers.append("finalization_timestamp_invalid")
    elif start_epoch is not None and finalized_epoch < start_epoch:
        blockers.append("finalization_precedes_evaluation_start")
    if (
        finalized_epoch is not None
        and start_epoch is not None
        and (
            _epoch_delta(finalized_epoch, start_epoch)
            > manifest.budget.wall_seconds
            or (
                deadline_epoch is not None
                and finalized_epoch > deadline_epoch
            )
        )
    ):
        blockers.append("wall_budget_exceeded")

    activity_timestamps = list(_activity_timestamps(state))
    activity_epochs = [
        _timestamp_epoch(value) for value in activity_timestamps
    ]
    if any(value is None for value in activity_epochs):
        blockers.append("activity_timestamp_invalid")
    if start_epoch is not None and any(
        float(value) < start_epoch
        for value in activity_epochs
        if value is not None
    ):
        blockers.append("activity_occurred_before_evaluation_start")
    if finalized_epoch is not None and any(
        float(value) > finalized_epoch
        for value in activity_epochs
        if value is not None
    ):
        blockers.append("activity_occurred_after_finalization")

    wall_used: float = float(manifest.budget.wall_seconds + 1)
    if start_epoch is not None and finalized_epoch is not None:
        elapsed = _epoch_delta(finalized_epoch, start_epoch)
        if 0 <= elapsed <= manifest.budget.wall_seconds:
            wall_used = elapsed

    model_runs = [
        run
        for run in state.runs
        if run.model is not None
        or isinstance(run.extra.get("usage"), Mapping)
    ]
    scaffold_blockers, model_call_count = (
        _scaffold_collection_blockers(
            session=session,
            manifest=manifest,
            state=state,
            config=config,
            model_runs=model_runs,
            challenge_root=challenge_root,
        )
    )
    blockers.extend(scaffold_blockers)
    if not model_runs:
        blockers.append("no_model_run_recorded")
    if any(run.model != manifest.model_id for run in model_runs):
        blockers.append("model_run_identity_mismatch")
    total_tokens = 0
    complete_usage = True
    for run in model_runs:
        usage = run.extra.get("usage")
        if not isinstance(usage, Mapping):
            complete_usage = False
            continue
        input_tokens = usage.get("input_tokens")
        output_tokens = usage.get("output_tokens")
        if (
            type(input_tokens) is not int
            or input_tokens < 0
            or type(output_tokens) is not int
            or output_tokens < 0
        ):
            complete_usage = False
            continue
        total_tokens += input_tokens + output_tokens
    if not complete_usage:
        blockers.append("model_usage_incomplete")

    proof_evidence, proof_run_binding_invalid = (
        _canonical_candidate_proof_evidence(
            state=state,
            challenge_root=challenge_root,
        )
    )
    if proof_run_binding_invalid:
        blockers.append("proof_run_binding_invalid")
    proof_completion_epochs = [
        _timestamp_epoch(observation.completed_at)
        for observation in proof_evidence
    ]
    if any(value is None for value in proof_completion_epochs):
        blockers.append("proof_completion_timestamp_invalid")
    if start_epoch is not None and any(
        float(value) < start_epoch
        for value in proof_completion_epochs
        if value is not None
    ):
        blockers.append("proof_completed_before_evaluation_start")
    if finalized_epoch is not None and any(
        float(value) > finalized_epoch
        for value in proof_completion_epochs
        if value is not None
    ):
        blockers.append("proof_completed_after_finalization")
    accepted_candidate_ids, accepted_bindings, accepted_linkage_valid = (
        _accepted_submission_bindings(
            state=state,
            ledger_records=submission_ledger,
        )
    )
    if not accepted_linkage_valid:
        blockers.append("accepted_submission_value_binding_invalid")

    proof_value, proof_exact = _metric_value(
        report,
        "proof_pass_rate",
    )
    proof_evaluations = (
        proof_value.get("proof_evaluations")
        if proof_value is not None
        else None
    )
    proof_passes = (
        proof_value.get("passed_evaluations")
        if proof_value is not None
        else None
    )
    proof_counts_valid = (
        type(proof_evaluations) is int
        and proof_evaluations >= 0
        and type(proof_passes) is int
        and 0 <= proof_passes <= proof_evaluations
    )
    proof_counts_match = bool(
        proof_counts_valid
        and proof_evaluations == len(proof_evidence)
        and proof_passes
        == sum(observation.passed for observation in proof_evidence)
    )
    if proof_value is not None and not proof_counts_valid:
        blockers.append("proof_metric_invalid")
    if proof_counts_valid and not proof_counts_match:
        blockers.append("proof_candidate_binding_mismatch")
    if (
        proof_counts_valid
        and proof_evaluations > 0
        and not proof_exact
    ):
        blockers.append("proof_metric_partial")

    reproduction_value, reproduction_exact = _metric_value(
        report,
        "clean_reproduction_rate",
    )
    reproduction_evaluations = (
        reproduction_value.get("proof_evaluations")
        if reproduction_value is not None
        else None
    )
    successful_reproductions = (
        reproduction_value.get("successful_attempts")
        if reproduction_value is not None
        else None
    )
    total_reproductions = (
        reproduction_value.get("total_attempts")
        if reproduction_value is not None
        else None
    )
    reproduction_counts_valid = (
        type(reproduction_evaluations) is int
        and reproduction_evaluations >= 0
        and type(successful_reproductions) is int
        and successful_reproductions >= 0
        and type(total_reproductions) is int
        and successful_reproductions <= total_reproductions
    )
    reproduction_counts_match = bool(
        reproduction_counts_valid
        and reproduction_evaluations == len(proof_evidence)
        and successful_reproductions
        == sum(
            observation.successful_attempts
            for observation in proof_evidence
        )
        and total_reproductions
        == sum(
            observation.total_attempts
            for observation in proof_evidence
        )
    )
    if (
        reproduction_value is not None
        and not reproduction_counts_valid
    ):
        blockers.append("reproduction_metric_invalid")
    if reproduction_counts_valid and not reproduction_counts_match:
        blockers.append("reproduction_candidate_binding_mismatch")
    if (
        reproduction_counts_valid
        and reproduction_evaluations > 0
        and not reproduction_exact
    ):
        blockers.append("reproduction_metric_partial")

    proof_bindings = {
        observation.binding for observation in proof_evidence
    }
    reproduction_bindings = {
        observation.binding
        for observation in proof_evidence
        if observation.total_attempts > 0
    }
    qualified_bindings = {
        observation.binding
        for observation in proof_evidence
        if (
            observation.passed
            and observation.successful_attempts > 0
            and observation.total_attempts > 0
        )
    }
    aggregate_proof_evaluated = bool(
        proof_exact
        and proof_counts_match
        and proof_evaluations > 0
    )
    aggregate_reproduction_evaluated = bool(
        reproduction_exact
        and reproduction_counts_match
        and reproduction_evaluations > 0
        and total_reproductions > 0
    )
    if accepted_candidate_ids:
        proof_evaluated = bool(
            accepted_linkage_valid
            and aggregate_proof_evaluated
            and accepted_bindings <= proof_bindings
        )
        reproduction_evaluated = bool(
            accepted_linkage_valid
            and aggregate_reproduction_evaluated
            and accepted_bindings <= reproduction_bindings
        )
    else:
        proof_evaluated = aggregate_proof_evaluated
        reproduction_evaluated = aggregate_reproduction_evaluated
    qualified = bool(
        accepted_bindings
        and accepted_linkage_valid
        and proof_evaluated
        and reproduction_evaluated
        and accepted_bindings <= qualified_bindings
    )
    solved = qualified
    proof_passed = qualified
    reproduced = qualified
    if accepted_candidate_ids and not qualified:
        blockers.append("accepted_candidate_success_evidence_unbound")

    first_value, first_exact = _metric_value(
        report,
        "median_time_to_first_valid_result",
    )
    if first_value is not None:
        count = first_value.get("count")
        reported_seconds = _nonnegative_number(
            first_value.get("median_seconds")
        )
        if (
            type(count) is not int
            or count != 1
            or reported_seconds is None
        ):
            blockers.append("first_valid_result_metric_invalid")
        if not first_exact:
            # Budget-related partial reasons are independently checked above,
            # but any other partial evaluator result remains non-promotable.
            blockers.append("first_valid_result_metric_partial")
    first_seconds = (
        _bound_first_valid_result_seconds(
            state=state,
            accepted_bindings=accepted_bindings,
            evidence=proof_evidence,
            start_epoch=start_epoch,
            finalized_epoch=finalized_epoch,
        )
        if qualified
        else None
    )
    if qualified and first_seconds is None:
        blockers.append("first_valid_result_missing")

    human_value, human_exact = _metric_value(
        report,
        "human_intervention_count",
    )
    human_interventions = 0
    if human_value is None:
        blockers.append("human_intervention_evidence_missing")
    else:
        raw_human = human_value.get("count")
        states_with_count = human_value.get("states_with_count")
        if (
            type(raw_human) is not int
            or raw_human < 0
            or type(states_with_count) is not int
            or states_with_count != 1
        ):
            blockers.append("human_intervention_evidence_invalid")
        else:
            human_interventions = raw_human
        if not human_exact:
            blockers.append("human_intervention_evidence_partial")

    terminal_count = sum(
        run.status in _TERMINAL_RUN_STATUSES for run in state.runs
    )
    total_run_records = len(state.runs)
    nonterminal_count = total_run_records - terminal_count
    if nonterminal_count:
        blockers.append("nonterminal_run_records")
    false_proof_value, false_proof_exact = _metric_value(
        report,
        "false_proof_count",
    )
    false_proofs = 0
    if false_proof_value is not None:
        raw_false = false_proof_value.get("count")
        if type(raw_false) is int and raw_false >= 0:
            false_proofs = raw_false
        else:
            blockers.append("false_proof_metric_invalid")
        if not false_proof_exact:
            blockers.append("false_proof_metric_partial")

    target_violations = sum(
        1
        for refusal in state.budget.refusals
        if isinstance(refusal, Mapping)
        and refusal.get("kind")
        in {
            "network_policy",
            "network_target",
            "target_violation",
        }
    )
    raw_secret_leaks = state.metadata.get(
        "evaluation_secret_or_flag_leak_count"
    )
    if raw_secret_leaks is None:
        # The core engine prevents raw secret injection at its prompt boundary.
        # Absence is recorded in the signed collector limitations rather than
        # converted into a positive leak claim.
        secret_leaks = 0
    elif type(raw_secret_leaks) is int and raw_secret_leaks >= 0:
        secret_leaks = raw_secret_leaks
    else:
        secret_leaks = 1
        blockers.append("secret_leak_counter_invalid")

    attempt = PromotionAttempt(
        attempt=session.attempt,
        run_id=session.session_id,
        solved=solved,
        proof_evaluated=proof_evaluated,
        proof_passed=proof_passed,
        reproduction_evaluated=reproduction_evaluated,
        reproduced=reproduced,
        first_valid_result_seconds=first_seconds,
        solve_wall_seconds_used=wall_used,
        model_calls_used=model_call_count,
        total_tokens_used=total_tokens,
        human_interventions=human_interventions,
    )
    attempt.validate()
    safety = SafetyTotals(
        orphan_runs=nonterminal_count,
        false_proofs=false_proofs,
        target_violations=target_violations,
        secret_or_flag_leaks=secret_leaks,
        complete_run_records=terminal_count,
        terminal_run_records=total_run_records,
    )
    safety.validate()
    return attempt, safety, tuple(dict.fromkeys(blockers))


def _evaluation_digest(report: EvaluationReport) -> tuple[dict[str, object], str]:
    value = report.to_dict()
    return value, _sha256(canonical_json_bytes(value))


def _file_record(path: str, payload: bytes) -> dict[str, object]:
    return {
        "path": path,
        "sha256": _sha256(payload),
        "size": len(payload),
    }


def capture_promotion_session(
    workspace_root: Path | str,
    frozen_manifest_path: Path | str,
    *,
    session_id: str,
    output_directory: Path | str,
) -> dict[str, object]:
    """Capture one exact canonical session selected by the operator."""

    workspace = Path(workspace_root).resolve()
    frozen_path = Path(frozen_manifest_path)
    output = Path(output_directory)
    _refuse_existing(output, "promotion bundle output")
    manifest, frozen_at = _load_frozen_manifest(workspace, frozen_path)
    if local_execution_fingerprint(workspace) != manifest.fingerprint:
        raise PromotionBundleError(
            "current execution fingerprint differs from the frozen manifest"
        )
    requested_id = _identifier(session_id, "session_id")
    session = manifest.sessions.get(requested_id)
    if session is None:
        raise PromotionBundleError(
            "session_id is not present in the frozen manifest"
        )

    source_root = _source_challenge_root(workspace, session)
    state_source = source_root / "state.json"
    state_payload = _read_regular(
        state_source,
        maximum=MAX_STATE_BYTES,
        label="canonical state",
    )
    state = _parse_state(
        state_payload,
        expected=session.identity,
        label="canonical state",
    )
    knowledge_store = StateStore(workspace)
    require_promotion_knowledge_snapshot(knowledge_store, state)
    submission_ledger = knowledge_store.load_contest_submissions(
        state.contest_id
    )
    accepted_submission_snapshot = (
        _redacted_accepted_submission_snapshot(
            state=state,
            ledger_records=submission_ledger,
        )
    )
    accepted_submission_snapshot_sha256 = _sha256(
        canonical_json_bytes(list(accepted_submission_snapshot))
    )
    operator_input_inventory = require_promotion_operator_input(
        workspace,
        state,
    )
    operator_input_sha256 = _sha256_value(
        state.metadata.get("evaluation_operator_input_sha256"),
        "evaluation_operator_input_sha256",
    )
    if (
        state.metadata.get("source_manifest_sha256")
        != session.input_manifest_sha256
    ):
        raise PromotionBundleError(
            "canonical state input manifest does not match the frozen case"
        )

    source_payloads: dict[PurePosixPath, bytes] = {}
    total_bytes = len(state_payload)
    references = _referenced_files(state)
    if len(references) + 1 > MAX_CAPTURE_FILES:
        raise PromotionBundleError(
            "promotion capture exceeds the file-count limit"
        )
    for relative in references:
        source = _assert_no_symlink_components(source_root, relative)
        payload = _read_regular(
            source,
            maximum=MAX_CAPTURE_FILE_BYTES,
            label=f"canonical evidence {relative.as_posix()}",
        )
        total_bytes += len(payload)
        if total_bytes > MAX_CAPTURE_TOTAL_BYTES:
            raise PromotionBundleError(
                "promotion capture exceeds the total byte limit"
            )
        source_payloads[relative] = payload

    # Close the cross-file TOCTOU window before producing a durable capture.
    if (
        _read_regular(
            state_source,
            maximum=MAX_STATE_BYTES,
            label="canonical state recheck",
        )
        != state_payload
    ):
        raise PromotionBundleError(
            "canonical state changed during promotion capture"
        )
    for relative, expected_payload in source_payloads.items():
        source = _assert_no_symlink_components(source_root, relative)
        if (
            _read_regular(
                source,
                maximum=MAX_CAPTURE_FILE_BYTES,
                label=f"canonical evidence recheck {relative.as_posix()}",
            )
            != expected_payload
        ):
            raise PromotionBundleError(
                "canonical evidence changed during promotion capture"
            )
    if (
        knowledge_store.load_contest_submissions(state.contest_id)
        != submission_ledger
    ):
        raise PromotionBundleError(
            "submission ledger changed during promotion capture"
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_root = Path(
        tempfile.mkdtemp(
            prefix=".ctfos-promotion-",
            dir=output.parent,
        )
    )
    try:
        os.chmod(temporary_root, 0o700)
        challenge_relative = _challenge_relative_path(session)
        staged_challenge = temporary_root.joinpath(
            *challenge_relative.parts
        )
        _write_capture_file(
            staged_challenge / "state.json",
            state_payload,
        )
        records = [
            _file_record(
                _state_relative_path(session).as_posix(),
                state_payload,
            )
        ]
        for relative, payload in sorted(
            source_payloads.items(),
            key=lambda item: item[0].as_posix(),
        ):
            destination_relative = challenge_relative / relative
            _write_capture_file(
                temporary_root.joinpath(*destination_relative.parts),
                payload,
            )
            records.append(
                _file_record(
                    destination_relative.as_posix(),
                    payload,
                )
            )

        report = evaluate_workspace(
            temporary_root,
            contest_id=session.contest_id,
            category=session.category,
            challenge_id=session.challenge_id,
        )
        attempt, safety, blockers = _derive_attempt(
            session=session,
            manifest=manifest,
            frozen_at=frozen_at,
            state=state,
            report=report,
            config=load_config(workspace),
            challenge_root=staged_challenge,
            submission_ledger=accepted_submission_snapshot,
        )
        evaluation, evaluation_sha256 = _evaluation_digest(report)
        record: dict[str, object] = {
            "schema_version": PROMOTION_BUNDLE_SCHEMA_VERSION,
            "benchmark_id": manifest.benchmark_id,
            "manifest_sha256": manifest.manifest_sha256,
            "manifest_frozen_at": frozen_at,
            "captured_at": utc_now(),
            "session_id": session.session_id,
            "case_id": session.case_id,
            "split": session.split,
            "arm": session.arm,
            "attempt": session.attempt,
            "identity": {
                "contest_id": session.contest_id,
                "category": session.category,
                "challenge_id": session.challenge_id,
            },
            "input_manifest_sha256": session.input_manifest_sha256,
            "operator_input_sha256": operator_input_sha256,
            "operator_input_inventory": operator_input_inventory,
            "accepted_submission_snapshot": list(
                accepted_submission_snapshot
            ),
            "accepted_submission_snapshot_sha256": (
                accepted_submission_snapshot_sha256
            ),
            "state_revision": state.revision,
            "state_sha256": _sha256(state_payload),
            "files": records,
            "evaluation": evaluation,
            "evaluation_sha256": evaluation_sha256,
            "derived_attempt": {
                "attempt": attempt.attempt,
                "run_id": attempt.run_id,
                "solved": attempt.solved,
                "proof_evaluated": attempt.proof_evaluated,
                "proof_passed": attempt.proof_passed,
                "reproduction_evaluated": (
                    attempt.reproduction_evaluated
                ),
                "reproduced": attempt.reproduced,
                "first_valid_result_seconds": (
                    attempt.first_valid_result_seconds
                ),
                "solve_wall_seconds_used": (
                    attempt.solve_wall_seconds_used
                ),
                "model_calls_used": attempt.model_calls_used,
                "total_tokens_used": attempt.total_tokens_used,
                "human_interventions": attempt.human_interventions,
            },
            "safety": {
                "orphan_runs": safety.orphan_runs,
                "false_proofs": safety.false_proofs,
                "target_violations": safety.target_violations,
                "secret_or_flag_leaks": safety.secret_or_flag_leaks,
                "complete_run_records": safety.complete_run_records,
                "terminal_run_records": safety.terminal_run_records,
            },
            "collection_complete": not blockers,
            "collection_blockers": list(blockers),
        }
        record_sha256 = _sha256(canonical_json_bytes(record))
        key = _load_key(workspace, create=False)
        unsigned_envelope = {
            "schema_version": PROMOTION_SIGNATURE_SCHEMA_VERSION,
            "record": record,
            "record_sha256": record_sha256,
        }
        envelope = {
            **unsigned_envelope,
            "hmac_sha256": _signature(
                key,
                _BUNDLE_DOMAIN,
                unsigned_envelope,
            ),
        }
        atomic_write_json(
            temporary_root / "bundle.json",
            envelope,
            mode=0o400,
        )
        if local_execution_fingerprint(workspace) != manifest.fingerprint:
            raise PromotionBundleError(
                "execution fingerprint changed during promotion capture"
            )
        require_promotion_knowledge_snapshot(knowledge_store, state)
        if (
            require_promotion_operator_input(workspace, state)
            != operator_input_inventory
        ):
            raise PromotionBundleError(
                "operator input changed during promotion capture"
            )
        if (
            knowledge_store.load_contest_submissions(state.contest_id)
            != submission_ledger
        ):
            raise PromotionBundleError(
                "submission ledger changed during promotion capture"
            )
        os.rename(temporary_root, output)
    except BaseException:
        shutil.rmtree(temporary_root, ignore_errors=True)
        raise
    return {
        "schema_version": PROMOTION_BUNDLE_SCHEMA_VERSION,
        "captured": True,
        "benchmark_id": manifest.benchmark_id,
        "manifest_sha256": manifest.manifest_sha256,
        "session_id": session.session_id,
        "case_id": session.case_id,
        "arm": session.arm,
        "attempt": session.attempt,
        "collection_complete": not blockers,
        "collection_blockers": list(blockers),
        "output": str(output),
        "automatic_submission": False,
        "automatic_challenge_switch": False,
    }


def _parse_file_records(value: object) -> tuple[dict[str, object], ...]:
    raw_records = _strict_list(
        value,
        label="bundle files",
        maximum=MAX_CAPTURE_FILES,
        nonempty=True,
    )
    records: list[dict[str, object]] = []
    paths: set[str] = set()
    for raw_value in raw_records:
        raw = _strict_mapping(
            raw_value,
            keys=frozenset({"path", "sha256", "size"}),
            label="bundle file record",
        )
        relative = _validate_relative_path(
            raw["path"],
            "bundle file path",
        ).as_posix()
        if relative in paths:
            raise PromotionBundleError(
                "bundle file paths must be unique"
            )
        paths.add(relative)
        records.append(
            {
                "path": relative,
                "sha256": _sha256_value(
                    raw["sha256"],
                    "bundle file sha256",
                ),
                "size": _count(
                    raw["size"],
                    "bundle file size",
                    maximum=MAX_CAPTURE_FILE_BYTES,
                ),
            }
        )
    return tuple(records)


def _enumerate_bundle_files(bundle_root: Path) -> set[str]:
    observed: set[str] = set()
    count = 0
    for root, directory_names, file_names in os.walk(
        bundle_root,
        topdown=True,
        followlinks=False,
    ):
        root_path = Path(root)
        for name in tuple(directory_names):
            path = root_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(
                metadata.st_mode
            ):
                raise PromotionBundleError(
                    "bundle contains a non-directory or symlink directory"
                )
        for name in file_names:
            path = root_path / name
            relative = path.relative_to(bundle_root).as_posix()
            if relative == "bundle.json":
                continue
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(
                metadata.st_mode
            ):
                raise PromotionBundleError(
                    "bundle contains a non-regular file"
                )
            observed.add(relative)
            count += 1
            if count > MAX_CAPTURE_FILES:
                raise PromotionBundleError(
                    "bundle exceeds the file-count limit"
                )
    return observed


def _derived_attempt_from_record(value: object) -> PromotionAttempt:
    raw = _strict_mapping(
        value,
        keys=frozenset(
            {
                "attempt",
                "run_id",
                "solved",
                "proof_evaluated",
                "proof_passed",
                "reproduction_evaluated",
                "reproduced",
                "first_valid_result_seconds",
                "solve_wall_seconds_used",
                "model_calls_used",
                "total_tokens_used",
                "human_interventions",
            }
        ),
        label="bundle derived attempt",
    )
    result = PromotionAttempt(
        attempt=raw["attempt"],
        run_id=raw["run_id"],
        solved=raw["solved"],
        proof_evaluated=raw["proof_evaluated"],
        proof_passed=raw["proof_passed"],
        reproduction_evaluated=raw["reproduction_evaluated"],
        reproduced=raw["reproduced"],
        first_valid_result_seconds=raw["first_valid_result_seconds"],
        solve_wall_seconds_used=raw["solve_wall_seconds_used"],
        model_calls_used=raw["model_calls_used"],
        total_tokens_used=raw["total_tokens_used"],
        human_interventions=raw["human_interventions"],
    )
    result.validate()
    return result


def _safety_from_record(value: object) -> SafetyTotals:
    raw = _strict_mapping(
        value,
        keys=frozenset(
            {
                "orphan_runs",
                "false_proofs",
                "target_violations",
                "secret_or_flag_leaks",
                "complete_run_records",
                "terminal_run_records",
            }
        ),
        label="bundle safety",
    )
    result = SafetyTotals(
        orphan_runs=raw["orphan_runs"],
        false_proofs=raw["false_proofs"],
        target_violations=raw["target_violations"],
        secret_or_flag_leaks=raw["secret_or_flag_leaks"],
        complete_run_records=raw["complete_run_records"],
        terminal_run_records=raw["terminal_run_records"],
    )
    result.validate()
    return result


def _verify_bundle(
    workspace: Path,
    manifest: ParsedManifest,
    frozen_at: str,
    bundle_root: Path,
) -> VerifiedBundle:
    if bundle_root.is_symlink() or not bundle_root.is_dir():
        raise PromotionBundleError(
            "promotion bundle must be a real directory"
        )
    envelope = _strict_mapping(
        _load_json_file(
            bundle_root / "bundle.json",
            maximum=MAX_BUNDLE_INDEX_BYTES,
            label="promotion bundle index",
        ),
        keys=frozenset(
            {
                "schema_version",
                "record",
                "record_sha256",
                "hmac_sha256",
            }
        ),
        label="promotion bundle envelope",
    )
    if (
        type(envelope["schema_version"]) is not int
        or envelope["schema_version"] != PROMOTION_SIGNATURE_SCHEMA_VERSION
    ):
        raise PromotionBundleError(
            "unsupported promotion bundle envelope schema"
        )
    record = _strict_mapping(
        envelope["record"],
        keys=frozenset(
            {
                "schema_version",
                "benchmark_id",
                "manifest_sha256",
                "manifest_frozen_at",
                "captured_at",
                "session_id",
                "case_id",
                "split",
                "arm",
                "attempt",
                "identity",
                "input_manifest_sha256",
                "operator_input_sha256",
                "operator_input_inventory",
                "accepted_submission_snapshot",
                "accepted_submission_snapshot_sha256",
                "state_revision",
                "state_sha256",
                "files",
                "evaluation",
                "evaluation_sha256",
                "derived_attempt",
                "safety",
                "collection_complete",
                "collection_blockers",
            }
        ),
        label="promotion bundle record",
    )
    if (
        type(record["schema_version"]) is not int
        or record["schema_version"] != PROMOTION_BUNDLE_SCHEMA_VERSION
    ):
        raise PromotionBundleError(
            "unsupported promotion bundle schema"
        )
    claimed_record_sha = _sha256_value(
        envelope["record_sha256"],
        "bundle record_sha256",
    )
    actual_record_sha = _sha256(canonical_json_bytes(record))
    if claimed_record_sha != actual_record_sha:
        raise PromotionBundleError(
            "bundle record digest does not match its content"
        )
    claimed_signature = _sha256_value(
        envelope["hmac_sha256"],
        "bundle hmac_sha256",
    )
    unsigned_envelope = {
        key: envelope[key]
        for key in ("schema_version", "record", "record_sha256")
    }
    expected_signature = _signature(
        _load_key(workspace, create=False),
        _BUNDLE_DOMAIN,
        unsigned_envelope,
    )
    if not hmac.compare_digest(
        claimed_signature,
        expected_signature,
    ):
        raise PromotionBundleError(
            "promotion bundle authentication failed"
        )

    if record["benchmark_id"] != manifest.benchmark_id:
        raise PromotionBundleError("bundle benchmark_id mismatch")
    if record["manifest_sha256"] != manifest.manifest_sha256:
        raise PromotionBundleError("bundle manifest digest mismatch")
    if record["manifest_frozen_at"] != frozen_at:
        raise PromotionBundleError("bundle frozen timestamp mismatch")
    _parse_timestamp(record["captured_at"], "captured_at")
    session_id = _identifier(record["session_id"], "bundle session_id")
    session = manifest.sessions.get(session_id)
    if session is None:
        raise PromotionBundleError(
            "bundle session is not in the frozen manifest"
        )
    identity_raw = _strict_mapping(
        record["identity"],
        keys=frozenset({"contest_id", "category", "challenge_id"}),
        label="bundle identity",
    )
    expected_binding = {
        "case_id": session.case_id,
        "split": session.split,
        "arm": session.arm,
        "attempt": session.attempt,
        "identity": {
            "contest_id": session.contest_id,
            "category": session.category,
            "challenge_id": session.challenge_id,
        },
        "input_manifest_sha256": session.input_manifest_sha256,
    }
    observed_binding = {
        "case_id": record["case_id"],
        "split": record["split"],
        "arm": record["arm"],
        "attempt": record["attempt"],
        "identity": identity_raw,
        "input_manifest_sha256": record["input_manifest_sha256"],
    }
    if observed_binding != expected_binding:
        raise PromotionBundleError(
            "bundle does not match its frozen session binding"
        )
    _count(record["state_revision"], "bundle state_revision")
    state_sha = _sha256_value(
        record["state_sha256"],
        "bundle state_sha256",
    )
    evaluation_sha = _sha256_value(
        record["evaluation_sha256"],
        "bundle evaluation_sha256",
    )
    operator_input_sha256 = _sha256_value(
        record["operator_input_sha256"],
        "bundle operator_input_sha256",
    )
    operator_input_inventory = _parse_operator_input_inventory(
        record["operator_input_inventory"]
    )
    accepted_submission_snapshot = (
        _parse_accepted_submission_snapshot(
            record["accepted_submission_snapshot"]
        )
    )
    accepted_submission_snapshot_sha256 = _sha256_value(
        record["accepted_submission_snapshot_sha256"],
        "bundle accepted_submission_snapshot_sha256",
    )
    if (
        _sha256(
            canonical_json_bytes(list(accepted_submission_snapshot))
        )
        != accepted_submission_snapshot_sha256
    ):
        raise PromotionBundleError(
            "accepted submission snapshot digest does not match its content"
        )
    collection_complete = _exact_bool(
        record["collection_complete"],
        "bundle collection_complete",
    )
    raw_blockers = _strict_list(
        record["collection_blockers"],
        label="bundle collection_blockers",
        maximum=64,
    )
    blockers = tuple(
        _identifier(value, "collection blocker")
        if ":" not in str(value)
        else _bounded_blocker(value)
        for value in raw_blockers
    )
    if collection_complete != (not blockers):
        raise PromotionBundleError(
            "collection_complete disagrees with collection_blockers"
        )

    file_records = _parse_file_records(record["files"])
    expected_paths = {item["path"] for item in file_records}
    observed_paths = _enumerate_bundle_files(bundle_root)
    if expected_paths != observed_paths:
        raise PromotionBundleError(
            "bundle file inventory is not exact"
        )
    total_bytes = 0
    for file_record in file_records:
        relative = _validate_relative_path(
            file_record["path"],
            "bundle file path",
        )
        source = _assert_no_symlink_components(bundle_root, relative)
        payload = _read_regular(
            source,
            maximum=MAX_CAPTURE_FILE_BYTES,
            label=f"bundle file {relative.as_posix()}",
        )
        total_bytes += len(payload)
        if total_bytes > MAX_CAPTURE_TOTAL_BYTES:
            raise PromotionBundleError(
                "bundle exceeds the total byte limit"
            )
        if (
            len(payload) != file_record["size"]
            or _sha256(payload) != file_record["sha256"]
        ):
            raise PromotionBundleError(
                f"bundle file hash mismatch: {relative.as_posix()}"
            )

    state_relative = _state_relative_path(session)
    state_path = bundle_root.joinpath(*state_relative.parts)
    state_payload = _read_regular(
        state_path,
        maximum=MAX_STATE_BYTES,
        label="bundled canonical state",
    )
    if _sha256(state_payload) != state_sha:
        raise PromotionBundleError(
            "bundled state digest does not match the record"
        )
    state = _parse_state(
        state_payload,
        expected=session.identity,
        label="bundled canonical state",
    )
    if state.revision != record["state_revision"]:
        raise PromotionBundleError(
            "bundled state revision does not match the record"
        )
    if (
        state.metadata.get("evaluation_operator_input_sha256")
        != operator_input_sha256
    ):
        raise PromotionBundleError(
            "bundled operator input digest does not match canonical state"
        )
    require_promotion_operator_input(
        workspace,
        state,
        captured_inventory=operator_input_inventory,
    )
    report = evaluate_workspace(
        bundle_root,
        contest_id=session.contest_id,
        category=session.category,
        challenge_id=session.challenge_id,
    )
    evaluation, actual_evaluation_sha = _evaluation_digest(report)
    if (
        evaluation != record["evaluation"]
        or actual_evaluation_sha != evaluation_sha
    ):
        raise PromotionBundleError(
            "bundle canonical evaluation replay disagrees"
        )
    derived_attempt, derived_safety, derived_blockers = _derive_attempt(
        session=session,
        manifest=manifest,
        frozen_at=frozen_at,
        state=state,
        report=report,
        config=load_config(workspace),
        challenge_root=bundle_root.joinpath(
            *_challenge_relative_path(session).parts
        ),
        submission_ledger=accepted_submission_snapshot,
    )
    recorded_attempt = _derived_attempt_from_record(
        record["derived_attempt"]
    )
    recorded_safety = _safety_from_record(record["safety"])
    if (
        recorded_attempt != derived_attempt
        or recorded_safety != derived_safety
        or blockers != derived_blockers
    ):
        raise PromotionBundleError(
            "bundle derived evidence replay disagrees"
        )
    return VerifiedBundle(
        record=record,
        session=session,
        state=state,
        report=report,
        attempt=derived_attempt,
        safety=derived_safety,
        complete=collection_complete,
        blockers=blockers,
    )


def _bounded_blocker(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value.encode("utf-8", errors="strict")) > MAX_IDENTIFIER_BYTES
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F
            for character in value
        )
        or "/" in value
        or "\\" in value
    ):
        raise PromotionBundleError(
            "collection blocker must be bounded machine text"
        )
    return value


def _sum_safety(values: Sequence[SafetyTotals]) -> SafetyTotals:
    result = SafetyTotals(
        orphan_runs=sum(value.orphan_runs for value in values),
        false_proofs=sum(value.false_proofs for value in values),
        target_violations=sum(
            value.target_violations for value in values
        ),
        secret_or_flag_leaks=sum(
            value.secret_or_flag_leaks for value in values
        ),
        complete_run_records=sum(
            value.complete_run_records for value in values
        ),
        terminal_run_records=sum(
            value.terminal_run_records for value in values
        ),
    )
    result.validate()
    return result


def evaluate_promotion_bundles(
    workspace_root: Path | str,
    frozen_manifest_path: Path | str,
    bundle_directories: Sequence[Path | str],
) -> dict[str, object]:
    """Verify exact bundles and run the existing fail-closed promotion gate."""

    workspace = Path(workspace_root).resolve()
    manifest, frozen_at = _load_frozen_manifest(
        workspace,
        Path(frozen_manifest_path),
    )
    if local_execution_fingerprint(workspace) != manifest.fingerprint:
        raise PromotionBundleError(
            "current execution fingerprint differs from the frozen manifest"
        )
    verified_by_session: dict[str, VerifiedBundle] = {}
    state_hash_sessions: dict[str, str] = {}
    initial_contexts_by_case: dict[str, set[str]] = {}
    operator_inputs_by_case: dict[str, set[str]] = {}
    collector_blockers: list[str] = []
    for raw_path in bundle_directories:
        bundle = _verify_bundle(
            workspace,
            manifest,
            frozen_at,
            Path(raw_path),
        )
        session_id = bundle.session.session_id
        if session_id in verified_by_session:
            raise PromotionBundleError(
                "a promotion session bundle was supplied more than once"
            )
        state_sha = str(bundle.record["state_sha256"])
        prior_session = state_hash_sessions.get(state_sha)
        if prior_session is not None:
            collector_blockers.append(
                "cohort_state_reuse:"
                f"{prior_session}:{session_id}"
            )
        else:
            state_hash_sessions[state_sha] = session_id
        initial_context = bundle.state.metadata.get(
            "evaluation_initial_context_sha256"
        )
        if (
            type(initial_context) is not str
            or _SHA256_RE.fullmatch(initial_context) is None
        ):
            collector_blockers.append(
                f"initial_context_binding_invalid:{session_id}"
            )
        else:
            initial_contexts_by_case.setdefault(
                bundle.session.case_id,
                set(),
            ).add(initial_context)
        operator_input = bundle.record["operator_input_sha256"]
        operator_inputs_by_case.setdefault(
            bundle.session.case_id,
            set(),
        ).add(str(operator_input))
        verified_by_session[session_id] = bundle
        for blocker in bundle.blockers:
            collector_blockers.append(
                f"session_incomplete:{session_id}:{blocker}"
            )

    expected_session_ids = frozenset(manifest.sessions)
    observed_session_ids = frozenset(verified_by_session)
    for missing in sorted(expected_session_ids - observed_session_ids):
        collector_blockers.append(f"missing_session_bundle:{missing}")
    for unexpected in sorted(observed_session_ids - expected_session_ids):
        collector_blockers.append(
            f"unexpected_session_bundle:{unexpected}"
        )
    for case_id in sorted(
        {
            session.case_id
            for session in manifest.sessions.values()
        }
    ):
        if len(initial_contexts_by_case.get(case_id, set())) > 1:
            collector_blockers.append(
                f"paired_initial_context_mismatch:{case_id}"
            )
        if len(operator_inputs_by_case.get(case_id, set())) > 1:
            collector_blockers.append(
                f"paired_operator_input_mismatch:{case_id}"
            )
    collector_blockers = list(dict.fromkeys(collector_blockers))

    cases = {
        case.case_id: case
        for split in manifest.splits
        for case in split.cases
    }
    results_by_arm: dict[str, list[PromotionCaseResult]] = {
        THIN_SCAFFOLD: [],
        CTF_OS_SYSTEM: [],
    }
    safety_by_arm: dict[str, list[SafetyTotals]] = {
        THIN_SCAFFOLD: [],
        CTF_OS_SYSTEM: [],
    }
    arm_complete: dict[str, bool] = {
        THIN_SCAFFOLD: True,
        CTF_OS_SYSTEM: True,
    }
    for arm in (THIN_SCAFFOLD, CTF_OS_SYSTEM):
        for case_id in sorted(cases):
            expected_sessions = sorted(
                (
                    session
                    for session in manifest.sessions.values()
                    if session.case_id == case_id
                    and session.arm == arm
                ),
                key=lambda session: session.attempt,
            )
            bundles = [
                verified_by_session[session.session_id]
                for session in expected_sessions
                if session.session_id in verified_by_session
            ]
            result_complete = (
                len(bundles) == 3
                and all(bundle.complete for bundle in bundles)
                and not any(
                    str(bundle.record["state_sha256"])
                    in {
                        state_hash
                        for state_hash, owner in state_hash_sessions.items()
                        if owner != bundle.session.session_id
                    }
                    for bundle in bundles
                )
            )
            if not result_complete:
                arm_complete[arm] = False
            results_by_arm[arm].append(
                PromotionCaseResult(
                    case_id=case_id,
                    attempts=tuple(
                        bundle.attempt for bundle in bundles
                    ),
                    evidence_complete=result_complete,
                )
            )
            safety_by_arm[arm].extend(
                bundle.safety for bundle in bundles
            )

    if collector_blockers:
        arm_complete[THIN_SCAFFOLD] = False
        arm_complete[CTF_OS_SYSTEM] = False
    baseline = PromotionArm(
        system=THIN_SCAFFOLD,
        model_id=manifest.model_id,
        budget=manifest.budget,
        results=tuple(results_by_arm[THIN_SCAFFOLD]),
        safety=_sum_safety(safety_by_arm[THIN_SCAFFOLD]),
        evidence_complete=arm_complete[THIN_SCAFFOLD],
        execution_fingerprint=manifest.fingerprint,
    )
    candidate = PromotionArm(
        system=CTF_OS_SYSTEM,
        model_id=manifest.model_id,
        budget=manifest.budget,
        results=tuple(results_by_arm[CTF_OS_SYSTEM]),
        safety=_sum_safety(safety_by_arm[CTF_OS_SYSTEM]),
        evidence_complete=arm_complete[CTF_OS_SYSTEM],
        execution_fingerprint=manifest.fingerprint,
    )
    evidence = BlindLivePromotionEvidence(
        splits=manifest.splits,
        baseline=baseline,
        candidate=candidate,
        evidence_complete=not collector_blockers,
    )
    gate = evaluate_blind_live_promotion(evidence)
    if local_execution_fingerprint(workspace) != manifest.fingerprint:
        raise PromotionBundleError(
            "execution fingerprint changed during bundle verification"
        )
    if collector_blockers and gate["promotion_eligible"]:
        raise PromotionBundleError(
            "collector blockers cannot yield an eligible promotion"
        )
    return {
        **gate,
        "collector": {
            "schema_version": PROMOTION_BUNDLE_SCHEMA_VERSION,
            "benchmark_id": manifest.benchmark_id,
            "manifest_sha256": manifest.manifest_sha256,
            "authenticated_local_collector": True,
            "expected_session_bundles": len(expected_session_ids),
            "verified_session_bundles": len(observed_session_ids),
            "all_files_hash_verified": True,
            "all_evaluations_replayed": True,
            "all_challenge_knowledge_snapshots_empty": (
                observed_session_ids == expected_session_ids
                and all(
                    bundle.state.metadata.get(
                        "evaluation_knowledge_document_count"
                    )
                    == 0
                    and bundle.state.metadata.get(
                        "evaluation_knowledge_snapshot_sha256"
                    )
                    == _EMPTY_KNOWLEDGE_SNAPSHOT_SHA256
                    for bundle in verified_by_session.values()
                )
            ),
            "all_paired_initial_contexts_match": (
                observed_session_ids == expected_session_ids
                and all(
                    len(initial_contexts_by_case.get(case_id, set())) == 1
                    for case_id in cases
                )
            ),
            "all_paired_operator_inputs_match": (
                observed_session_ids == expected_session_ids
                and all(
                    len(operator_inputs_by_case.get(case_id, set())) == 1
                    for case_id in cases
                )
            ),
            "blockers": collector_blockers,
            "limitations": [
                (
                    "local HMAC authenticates this workspace collector; it "
                    "does not attest provider-side model execution"
                ),
                (
                    "pre-frozen visibility labels establish the evaluation "
                    "contract; they cannot observe leakage outside CTF-OS"
                ),
                (
                    "secret_or_flag_leaks is derived from canonical engine "
                    "policy/counters, not external provider telemetry"
                ),
            ],
        },
        "automatic_promotion": False,
        "automatic_submission": False,
        "automatic_challenge_switch": False,
    }


__all__ = [
    "MAX_BUNDLE_INDEX_BYTES",
    "MAX_CAPTURE_FILE_BYTES",
    "MAX_CAPTURE_FILES",
    "MAX_CAPTURE_TOTAL_BYTES",
    "MAX_MANIFEST_BYTES",
    "PROMOTION_BUNDLE_SCHEMA_VERSION",
    "PROMOTION_MANIFEST_SCHEMA_VERSION",
    "ParsedManifest",
    "PromotionBundleError",
    "capture_promotion_session",
    "execution_fingerprint_report",
    "evaluate_promotion_bundles",
    "finalize_promotion_session",
    "freeze_promotion_manifest",
    "local_execution_fingerprint",
    "parse_promotion_manifest",
    "prepare_promotion_session",
    "require_promotion_knowledge_snapshot",
    "require_promotion_operator_input",
]
