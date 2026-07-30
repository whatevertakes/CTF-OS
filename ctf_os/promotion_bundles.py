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
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

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
from ctf_os.evaluation import EvaluationReport, evaluate_workspace
from ctf_os.config import load_config
from ctf_os.models import (
    ChallengeIdentity,
    ChallengeState,
    ExperimentStatus,
    RunStatus,
    SubmissionStatus,
    utc_now,
)
from ctf_os.store import StateStore
from ctf_os.store.atomic import (
    atomic_write_bytes,
    atomic_write_json,
    canonical_json_bytes,
    strict_json_loads,
)
from ctf_os.store.upgrades import upgrade_state, validate_state_protocol_shape


PROMOTION_MANIFEST_SCHEMA_VERSION = 1
PROMOTION_BUNDLE_SCHEMA_VERSION = 1
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


def local_execution_fingerprint(
    workspace_root: Path | str,
) -> BenchmarkExecutionFingerprint:
    """Derive the local model/tool/image fingerprint used for preparation."""

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
    model_configuration = asdict(config.models)
    result = BenchmarkExecutionFingerprint(
        tool_manifest_sha256=_sha256(tool_manifest),
        image_sha256=image_digest.removeprefix("sha256:"),
        model_config_sha256=_sha256(
            canonical_json_bytes(model_configuration)
        ),
    )
    result.validate()
    return result


def execution_fingerprint_report(
    workspace_root: Path | str,
) -> dict[str, object]:
    """Return the exact values an operator should freeze into a manifest."""

    fingerprint = local_execution_fingerprint(workspace_root)
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
        },
    }


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
            "current model/tool/image fingerprint does not match the "
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
    if all(
        state.metadata.get(key) == expected
        for key, expected in binding.items()
    ):
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
            "automatic_challenge_start": False,
        }
    for key, expected in binding.items():
        observed = state.metadata.get(key)
        if observed is not None and observed != expected:
            raise PromotionBundleError(
                f"canonical state already has a conflicting {key}"
            )

    def apply(current: ChallengeState) -> None:
        for key, expected in binding.items():
            current.metadata[key] = expected
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
        current.metadata["human_intervention_count"] = human_count
        current.metadata[
            "evaluation_human_interventions_finalized"
        ] = True
        current.metadata[
            "evaluation_secret_or_flag_leak_count"
        ] = leak_count
        current.metadata["evaluation_safety_finalized"] = True
        current.metadata["evaluation_finalized_at"] = utc_now()

    finalized = store.update(
        session.identity,
        apply,
        expected_revision=state.revision,
    )
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


def _derive_attempt(
    *,
    session: ManifestSession,
    manifest: ParsedManifest,
    frozen_at: str,
    state: ChallengeState,
    report: EvaluationReport,
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
    if (
        state.metadata.get(
            "evaluation_human_interventions_finalized"
        )
        is not True
    ):
        blockers.append("human_interventions_not_finalized")
    if state.metadata.get("evaluation_safety_finalized") is not True:
        blockers.append("safety_counters_not_finalized")
    finalized_epoch = _timestamp_epoch(
        state.metadata.get("evaluation_finalized_at")
    )
    activity_timestamps: list[object] = [
        run.created_at for run in state.runs
    ]
    activity_timestamps.extend(
        artifact.created_at for artifact in state.artifacts
    )
    activity_timestamps.extend(
        candidate.created_at for candidate in state.candidates
    )
    activity_timestamps.extend(
        submission.submitted_at
        for submission in state.submissions
        if submission.submitted_at is not None
    )
    activity_epochs = [
        _timestamp_epoch(value) for value in activity_timestamps
    ]
    if finalized_epoch is None:
        blockers.append("finalization_timestamp_invalid")
    elif any(value is None for value in activity_epochs):
        blockers.append("activity_timestamp_invalid")
    elif any(
        float(value) > finalized_epoch
        for value in activity_epochs
        if value is not None
    ):
        blockers.append("activity_occurred_after_finalization")

    model_runs = [
        run
        for run in state.runs
        if run.model is not None
        or isinstance(run.extra.get("usage"), Mapping)
    ]
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

    solved = any(
        submission.status is SubmissionStatus.ACCEPTED
        for submission in state.submissions
    )
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
    proof_evaluated = bool(
        proof_counts_valid and proof_evaluations > 0
    )
    proof_passed = bool(
        proof_counts_valid and proof_passes > 0
    )
    if proof_value is not None and not proof_counts_valid:
        blockers.append("proof_metric_invalid")
    if proof_evaluated and not proof_exact:
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
    reproduction_counts_valid = (
        type(reproduction_evaluations) is int
        and reproduction_evaluations >= 0
    )
    reproduction_evaluated = bool(
        reproduction_counts_valid and reproduction_evaluations > 0
    )
    # A canonical proof pass already includes its required clean repetitions.
    # The aggregate clean-reproduction metric independently establishes that
    # the reproduction observations were readable.
    reproduced = bool(
        proof_passed
        and reproduction_evaluated
        and reproduction_exact
    )
    if (
        reproduction_value is not None
        and not reproduction_counts_valid
    ):
        blockers.append("reproduction_metric_invalid")
    if reproduction_evaluated and not reproduction_exact:
        blockers.append("reproduction_metric_partial")

    first_value, first_exact = _metric_value(
        report,
        "median_time_to_first_valid_result",
    )
    first_seconds: float | None = None
    if first_value is not None:
        count = first_value.get("count")
        candidate_seconds = _nonnegative_number(
            first_value.get("median_seconds")
        )
        if type(count) is int and count == 1 and candidate_seconds is not None:
            first_seconds = candidate_seconds
        else:
            blockers.append("first_valid_result_metric_invalid")
        if not first_exact:
            # Budget-related partial reasons are independently checked above,
            # but any other partial evaluator result remains non-promotable.
            blockers.append("first_valid_result_metric_partial")
    if (solved or (proof_passed and reproduced)) and first_seconds is None:
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

    wall_used = state.budget.spent_seconds
    if type(wall_used) is not int or wall_used < 0:
        blockers.append("wall_usage_invalid")
        wall_used = manifest.budget.wall_seconds + 1

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
        model_calls_used=len(model_runs),
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
]
