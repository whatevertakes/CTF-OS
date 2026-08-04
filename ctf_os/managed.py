"""Managed one-challenge orchestration.

This module owns the durable Captain -> fixed three-role wave -> deterministic
action -> checkpoint lifecycle.  It deliberately has no contest scheduler and
never falls back to assisted solving after a managed failure.
"""

from __future__ import annotations

import hashlib
import math
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from ctf_os.adapters import get_adapter
from ctf_os.benchmark import CTF_OS_SYSTEM
from ctf_os.budget import (
    BudgetExhausted,
    remaining_seconds as budget_remaining_seconds,
)
from ctf_os.capabilities import (
    CapabilityError,
    inspect_pinned_capabilities,
    required_managed_capabilities_for_category,
)
from ctf_os.codex import BatchResult, Role
from ctf_os.codex.contracts import (
    MANAGED_CRYPTO_METAMORPHIC_ACTION_KIND,
    MANAGED_DATA_TRANSCRIPT_ACTION_KIND,
    MANAGED_FORENSIC_ASSERTION_ACTION_KIND,
    MANAGED_MISC_TRANSFORM_ACTION_KIND,
    MANAGED_PWN_CRASH_ACTION_KIND,
    MANAGED_PWN_EXPLOIT_EFFECT_ACTION_KIND,
    MANAGED_PWN_INTERACTION_ACTION_KIND,
    MANAGED_REV_ACCEPTED_INPUT_ACTION_KIND,
    MANAGED_TYPED_GATE_ACTION_KINDS,
    MANAGED_WEB_ACTIVE_PROBE_ACTION_KIND,
    MANAGED_WEB_IMPACT_ACTION_KIND,
)
from ctf_os.contracts.data_transcript_v1 import (
    DATA_TRANSCRIPT_V1_CONTRACT_FINGERPRINT,
    DATA_TRANSCRIPT_V1_MAX_DOCUMENT_BYTES,
    DataTranscriptContractError,
    parse_data_transcript_v1_recipe,
)
from ctf_os.contracts.managed_rejection_v1 import (
    MANAGED_REJECTION_V1_MAX_ATTEMPT,
    MANAGED_REJECTION_V1_MAX_ISSUES,
    MANAGED_REJECTION_V1_MAX_OMITTED,
    ManagedRejectionV1ContractError,
    build_managed_rejection_v1,
    validate_managed_rejection_v1_mapping,
)
from ctf_os.contracts.pwn_crash_v1 import (
    PWN_CRASH_V1_CONTRACT_FINGERPRINT,
    PWN_CRASH_V1_CONTRACT_ID,
    PWN_CRASH_V1_CONTRACT_VERSION,
    PWN_CRASH_V1_MAX_INPUT_BYTES,
    PWN_CRASH_V1_PROTOCOL,
)
from ctf_os.contracts.pwn_interaction_v1 import (
    PWN_INTERACTION_V1_CONTRACT_FINGERPRINT,
    PWN_INTERACTION_V1_MAX_DOCUMENT_BYTES,
    PwnInteractionRecipeError,
    parse_pwn_interaction_v1_recipe,
)
from ctf_os.engine.challenge import (
    WAVE_ROLES,
    ChallengeEngine,
    EngineError,
    SessionAlreadyRunning,
    managed_request_binding_errors,
)
from ctf_os.engine.checkpoint_projection import (
    MANAGED_REGISTERED_SELECTION_KEY,
    checkpoint_action_projection_metadata,
    checkpoint_action_references,
    managed_registered_contract_is_bounded,
    managed_registered_selection_binding,
    managed_registered_selection_matches,
)
from ctf_os.engine.failure_capsule import (
    bounded_pwn_crash_failure_reason,
    build_failure_capsule,
    selected_pwn_crash_failure_reason,
)
from ctf_os.engine.managed_oracle_preissue import (
    MANAGED_ORACLE_PREISSUE_CRYPTO,
    MANAGED_ORACLE_PREISSUE_CRYPTO_TRANSCRIPT,
    MANAGED_ORACLE_PREISSUE_MISC,
    MANAGED_ORACLE_PREISSUE_MISC_TRANSCRIPT,
    MANAGED_ORACLE_PREISSUE_STATE_KEY,
    ManagedOraclePreissueError,
    validate_public_record as validate_managed_oracle_preissue_public_record,
)
from ctf_os.engine.rev_acceptance import (
    REV_ACCEPTANCE_MAX_INPUT_BYTES,
    REV_ACCEPTANCE_MAX_SPEC_BYTES,
    RevAcceptanceContractError,
    RevAcceptanceOperatorSpec,
    canonical_json_bytes as rev_canonical_json_bytes,
    sha256 as rev_sha256,
    validate_rev_acceptance_evaluation,
    validate_rev_acceptance_expected_oracle,
)
from ctf_os.managed_continuity import (
    ManagedContinuityContractError,
    THREAD_CONTINUITY_ALWAYS_FRESH_ROLES,
    THREAD_CONTINUITY_CONTRACT_VERSION,
    THREAD_CONTINUITY_ELIGIBLE_ROLES,
    THREAD_CONTINUITY_RUN_KEY,
    THREAD_CONTINUITY_SESSION_KEY,
    build_lane_identity,
    build_run_audit,
    build_session_metadata,
    run_audit_errors,
    session_metadata_errors,
    source_generation,
    thread_id_sha256,
    valid_thread_id,
    validate_thread_continuity_policy,
)
from ctf_os.managed_budget import (
    MANAGED_WAVE_BUDGET_GUARD_KEY,
    MANAGED_WAVE_BUDGET_GUARD_V2_KEY,
    ManagedWaveBudgetContractError,
    build_managed_wave_budget_guard_v2,
)
from ctf_os.models import (
    ACTIVE_HYPOTHESIS_STATUSES,
    MANAGED_SHELL_COMMAND_PROTOCOL,
    BudgetMode,
    ChallengeIdentity,
    ChallengeState,
    ChallengeStatus,
    Checkpoint,
    distinct_complete_active_hypotheses,
    Experiment,
    ExperimentKind,
    ExperimentStatus,
    FactKind,
    ManagedCycle,
    ManagedWave,
    ModelValidationError,
    RunOrigin,
    RunReference,
    RunStatus,
    SessionMode,
    SessionStatus,
    SolveSession,
    TargetStatus,
    WaveKind,
    utc_now,
)
from ctf_os.schema import (
    RUN_ENVELOPE_SCHEMA_VERSION,
    STATE_SCHEMA_VERSION,
    WORKER_RESULT_SCHEMA_VERSION,
)
from ctf_os.scaffold_binding import (
    SCAFFOLD_LAUNCH_METADATA_KEY,
    ScaffoldBindingError,
    managed_command_contract_sha256,
    validate_scaffold_launch_record,
)
from ctf_os.store import ChallengeLock, LockTimeout, sha256_file
from ctf_os.sandbox.files import SafeFileError, read_bounded_regular
from ctf_os.store.atomic import (
    StrictJSONError,
    atomic_write_json,
    canonical_json_bytes,
    read_json,
    strict_json_loads,
)
from ctf_os.workspace_publish import (
    WorkspacePublishProposalRejected,
    canonical_workspace_hash,
    publish_builder_file,
    reconcile_workspace_publishes,
)


CapabilityProbe = Callable[[str], Mapping[str, Any]]
_STOP_STATUSES = frozenset(
    {
        ChallengeStatus.PAUSED,
        ChallengeStatus.NEEDS_HUMAN,
        ChallengeStatus.READY_TO_SUBMIT,
        ChallengeStatus.SOLVED,
        ChallengeStatus.ABANDONED,
        ChallengeStatus.STALLED,
    }
)
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
_PWN_CRASH_ENGINE_COMMAND = "ctfos-engine:pwn-crash-v1"
_PWN_CRASH_ENGINE_EXECUTOR = "pwn_crash_differential_v1"
_MANAGED_TYPED_GATE_ENGINE_COMMAND = "ctfos-engine:typed-gate-v1"
_MANAGED_TYPED_GATE_ENGINE_EXECUTOR = "managed_typed_gate_v1"
_MANAGED_LOCAL_PWN_TYPED_GATE_KINDS = frozenset(
    {
        MANAGED_PWN_EXPLOIT_EFFECT_ACTION_KIND,
        MANAGED_PWN_INTERACTION_ACTION_KIND,
    }
)
_MANAGED_PWN_REMOTE_TARGET_REJECTION = (
    "typed_gate_pwn_local_only_with_remote_target"
)
_MAX_MANAGED_REJECTED_ACTIONS = 64
_MAX_MANAGED_TYPED_GATE_PATHS = 4
_MANAGED_TYPED_GATE_CATEGORIES = {
    MANAGED_PWN_EXPLOIT_EFFECT_ACTION_KIND: "pwn",
    MANAGED_PWN_INTERACTION_ACTION_KIND: "pwn",
    MANAGED_REV_ACCEPTED_INPUT_ACTION_KIND: "reversing",
    MANAGED_WEB_IMPACT_ACTION_KIND: "web",
    MANAGED_WEB_ACTIVE_PROBE_ACTION_KIND: "web",
    MANAGED_CRYPTO_METAMORPHIC_ACTION_KIND: "crypto",
    MANAGED_FORENSIC_ASSERTION_ACTION_KIND: "forensics",
    MANAGED_MISC_TRANSFORM_ACTION_KIND: "misc",
}
_MANAGED_TYPED_GATE_PATH_FIELDS = {
    MANAGED_PWN_EXPLOIT_EFFECT_ACTION_KIND: (
        "payload_artifact_path",
    ),
    MANAGED_PWN_INTERACTION_ACTION_KIND: (
        "recipe_artifact_path",
    ),
    MANAGED_REV_ACCEPTED_INPUT_ACTION_KIND: (
        "operator_spec_artifact_path",
        "accepted_input_artifact_path",
    ),
    MANAGED_WEB_IMPACT_ACTION_KIND: (
        "operator_spec_artifact_path",
        "driver_artifact_path",
    ),
    MANAGED_WEB_ACTIVE_PROBE_ACTION_KIND: (
        "operator_spec_artifact_path",
        "driver_artifact_path",
    ),
    MANAGED_CRYPTO_METAMORPHIC_ACTION_KIND: (
        "solver_artifact_path",
        "original_parameters_artifact_path",
    ),
    MANAGED_FORENSIC_ASSERTION_ACTION_KIND: (
        "operator_spec_artifact_path",
    ),
    MANAGED_MISC_TRANSFORM_ACTION_KIND: (
        "spec_artifact_path",
    ),
    MANAGED_DATA_TRANSCRIPT_ACTION_KIND: (
        "recipe_artifact_path",
    ),
}
_MANAGED_TYPED_GATE_KEYS = {
    MANAGED_PWN_EXPLOIT_EFFECT_ACTION_KIND: frozenset(
        {
            "kind",
            "description",
            "parent_experiment_id",
            "payload_artifact_path",
            "timeout_seconds",
        }
    ),
    MANAGED_PWN_INTERACTION_ACTION_KIND: frozenset(
        {
            "kind",
            "description",
            "parent_experiment_id",
            "recipe_artifact_path",
            "timeout_seconds",
        }
    ),
    MANAGED_REV_ACCEPTED_INPUT_ACTION_KIND: frozenset(
        {
            "kind",
            "operator_spec_artifact_path",
            "operator_spec_sha256",
            "accepted_input_artifact_path",
            "accepted_input_sha256",
            "declared_argv",
            "expected_oracle",
        }
    ),
    MANAGED_WEB_IMPACT_ACTION_KIND: frozenset(
        {
            "kind",
            "description",
            "operator_spec_artifact_path",
            "driver_artifact_path",
            "hypothesis_ids",
            "timeout_seconds",
        }
    ),
    MANAGED_WEB_ACTIVE_PROBE_ACTION_KIND: frozenset(
        {
            "kind",
            "description",
            "operator_spec_artifact_path",
            "driver_artifact_path",
            "hypothesis_ids",
            "timeout_seconds",
        }
    ),
    MANAGED_CRYPTO_METAMORPHIC_ACTION_KIND: frozenset(
        {
            "kind",
            "description",
            "candidate_id",
            "solver_artifact_path",
            "original_parameters_artifact_path",
            "oracle_preissue_id",
            "runtime",
        }
    ),
    MANAGED_FORENSIC_ASSERTION_ACTION_KIND: frozenset(
        {
            "kind",
            "description",
            "operator_spec_artifact_path",
            "hypothesis_ids",
            "timeout_seconds",
        }
    ),
    MANAGED_MISC_TRANSFORM_ACTION_KIND: frozenset(
        {
            "kind",
            "description",
            "candidate_id",
            "spec_artifact_path",
            "oracle_preissue_id",
        }
    ),
    MANAGED_DATA_TRANSCRIPT_ACTION_KIND: frozenset(
        {
            "kind",
            "oracle_preissue_id",
            "recipe_artifact_path",
        }
    ),
}
_MANAGED_TYPED_GATE_TIMEOUT_LIMITS = {
    MANAGED_PWN_EXPLOIT_EFFECT_ACTION_KIND: 3600,
    MANAGED_PWN_INTERACTION_ACTION_KIND: 3600,
    MANAGED_WEB_IMPACT_ACTION_KIND: 86_400,
    MANAGED_WEB_ACTIVE_PROBE_ACTION_KIND: 86_400,
    MANAGED_FORENSIC_ASSERTION_ACTION_KIND: 86_400,
}


class ManagedError(EngineError):
    """Managed execution failed without changing to another solve mode."""


class ManagedRegisteredExperimentReferenceError(ManagedError):
    """A Captain pending-experiment reference failed canonical binding."""


class ManagedPreflightBlocked(ManagedError):
    def __init__(self, issues: Sequence[str]) -> None:
        self.issues = tuple(issues)
        super().__init__("managed preflight blocked: " + "; ".join(self.issues))


class ManagedWaveBudgetInsufficient(ManagedError):
    """A Captain completed, but the full next wave cannot fit safely."""

    def __init__(
        self,
        state: ChallengeState,
        audit: Mapping[str, object],
    ) -> None:
        self.state = state
        self.audit = dict(audit)
        remaining_ms = self.audit.get("remaining_budget_ms")
        minimum_ms = self.audit.get("minimum_required_ms")
        super().__init__(
            "insufficient_budget_for_wave: "
            f"remaining_ms={remaining_ms}, minimum_required_ms={minimum_ms}"
        )


@dataclass(frozen=True, slots=True)
class PreflightReport:
    ok: bool
    identity: str
    state_revision: int
    configuration_epoch: int
    checks: Mapping[str, Any]
    issues: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "identity": self.identity,
            "state_revision": self.state_revision,
            "configuration_epoch": self.configuration_epoch,
            "checks": dict(self.checks),
            "issues": list(self.issues),
        }


@dataclass(frozen=True, slots=True)
class BuilderPublishRejection:
    run_id: str
    proposal_ordinal: int
    code: str


@dataclass(frozen=True, slots=True)
class BuilderPublishOutcome:
    published_count: int
    rejection: BuilderPublishRejection | None = None


@dataclass(frozen=True, slots=True)
class ManagedTypedGateRegistrationOutcome:
    experiment_ids: tuple[str, ...] = ()
    rejection_code: str | None = None


def _managed_rejection_issue_sort_key(
    issue: Mapping[str, object],
) -> tuple[object, ...]:
    kind = issue.get("kind")
    if kind == "role_output":
        return (0, issue.get("pointer"), issue.get("code"))
    if kind == "reported_artifact":
        return (1, issue.get("pointer"), issue.get("code"))
    return (
        2,
        issue.get("proposal_ordinal"),
        issue.get("code"),
    )


def _merge_builder_publish_rejection(
    existing: object,
    *,
    attempt: int,
    proposal_ordinal: int,
    code: str,
) -> dict[str, object]:
    publication = build_managed_rejection_v1(
        role=Role.BUILDER.value,
        attempt=attempt,
        artifact_publication_rejections=(
            {
                "code": code,
                "kind": "artifact_publication",
                "proposal_ordinal": proposal_ordinal,
            },
        ),
    )
    if existing is None:
        return publication
    current = validate_managed_rejection_v1_mapping(existing)
    if current["role"] != Role.BUILDER.value:
        raise ManagedRejectionV1ContractError(
            "Builder rejection role does not match its run"
        )
    new_issue = publication["issues"][0]
    assert isinstance(new_issue, dict)
    current_issues = current["issues"]
    assert isinstance(current_issues, list)
    combined = [
        issue
        for issue in current_issues
        if not (
            isinstance(issue, Mapping)
            and issue.get("kind") == "artifact_publication"
            and issue.get("proposal_ordinal") == proposal_ordinal
        )
    ]
    combined.append(new_issue)
    unique: dict[tuple[object, ...], dict[str, object]] = {}
    for issue in combined:
        assert isinstance(issue, dict)
        unique.setdefault(
            _managed_rejection_issue_sort_key(issue),
            dict(issue),
        )
    ordered = sorted(
        unique.values(),
        key=_managed_rejection_issue_sort_key,
    )
    selected = ordered[:MANAGED_REJECTION_V1_MAX_ISSUES]
    new_identity = _managed_rejection_issue_sort_key(new_issue)
    if (
        len(ordered) > MANAGED_REJECTION_V1_MAX_ISSUES
        and all(
            _managed_rejection_issue_sort_key(issue) != new_identity
            for issue in selected
        )
    ):
        selected = sorted(
            [
                *selected[: MANAGED_REJECTION_V1_MAX_ISSUES - 1],
                new_issue,
            ],
            key=_managed_rejection_issue_sort_key,
        )
    merged = {
        "attempt": max(int(current["attempt"]), attempt),
        "authority": publication["authority"],
        "issues": selected,
        "omitted_count": min(
            MANAGED_REJECTION_V1_MAX_OMITTED,
            int(current["omitted_count"])
            + max(0, len(ordered) - len(selected)),
        ),
        "role": Role.BUILDER.value,
        "schema_version": publication["schema_version"],
    }
    return validate_managed_rejection_v1_mapping(merged)


def _stable_id(prefix: str, *parts: object) -> str:
    payload = "\0".join(str(part) for part in parts)
    return f"{prefix}-{uuid.uuid5(uuid.NAMESPACE_URL, payload).hex[:24]}"


def _bounded_checkpoint_note(*parts: str | None) -> str:
    text = "\n".join(
        item.strip()
        for item in parts
        if item is not None and item.strip()
    )
    encoded = text.encode("utf-8")
    if len(encoded) <= 4096:
        return text
    suffix = "…".encode("utf-8")
    return (
        encoded[: 4096 - len(suffix)].decode("utf-8", errors="ignore")
        + suffix.decode("utf-8")
    )


def _captain_failure_checkpoint_reason(
    result: BatchResult,
) -> tuple[str, str]:
    """Classify terminal Captain transport failures before contract errors."""

    if any(
        failure.kind == "challenge_budget_expired"
        for failure in result.failures
    ):
        return (
            "challenge_budget_expired",
            "Challenge wall-clock budget expired during the Captain model call",
        )
    if result.attempts and result.attempts[-1].timed_out:
        return (
            "captain_timed_out",
            (
                "Captain model call timed out before producing a "
                "contract-valid result"
            ),
        )
    return (
        "captain_contract_invalid",
        "Captain result was not contract-valid",
    )


def _safe_managed_artifact_locator(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    raw_parts = value.split("/")
    path = PurePosixPath(value)
    if (
        not value
        or value == "."
        or "\x00" in value
        or "\\" in value
        or len(value.encode("utf-8")) > 4096
        or path.is_absolute()
        or ".." in path.parts
        or any(
            part in {"", ".", ".."}
            or len(part.encode("utf-8")) > 255
            for part in raw_parts
        )
    ):
        return None
    return value


def _managed_typed_gate_category_matches(
    kind: str,
    adapter_name: str,
) -> bool:
    if kind == MANAGED_DATA_TRANSCRIPT_ACTION_KIND:
        return adapter_name in {"crypto", "misc"}
    return _MANAGED_TYPED_GATE_CATEGORIES.get(kind) == adapter_name


def _managed_typed_gate_action_shape_error(
    action: object,
) -> str | None:
    """Validate the exact non-semantic shape before any workspace publish."""

    if not isinstance(action, Mapping):
        return "typed_gate_action_invalid"
    kind = action.get("kind")
    if (
        type(kind) is not str
        or kind not in MANAGED_TYPED_GATE_ACTION_KINDS
        or set(action) != _MANAGED_TYPED_GATE_KEYS[kind]
        or (
            kind
            not in {
                MANAGED_REV_ACCEPTED_INPUT_ACTION_KIND,
                MANAGED_DATA_TRANSCRIPT_ACTION_KIND,
            }
            and type(action.get("description")) is not str
        )
    ):
        return "typed_gate_action_invalid"
    locators = [
        _safe_managed_artifact_locator(action.get(field))
        for field in _MANAGED_TYPED_GATE_PATH_FIELDS[kind]
    ]
    if (
        any(locator is None for locator in locators)
        or len(set(locators)) != len(locators)
    ):
        return "typed_gate_path_invalid"
    hypothesis_ids = action.get("hypothesis_ids", [])
    if (
        type(hypothesis_ids) is not list
        or len(hypothesis_ids) > 64
        or any(
            type(item) is not str
            or not item
            or len(item) > 256
            for item in hypothesis_ids
        )
        or len(set(hypothesis_ids)) != len(hypothesis_ids)
    ):
        return "typed_gate_hypothesis_invalid"
    maximum = _MANAGED_TYPED_GATE_TIMEOUT_LIMITS.get(kind)
    if maximum is not None:
        timeout = action.get("timeout_seconds")
        if (
            type(timeout) is not int
            or not 1 <= timeout <= maximum
        ):
            return "typed_gate_timeout_invalid"
    for field in (
        "candidate_id",
        "parent_experiment_id",
        "oracle_preissue_id",
    ):
        if field in action:
            value = action.get(field)
            if (
                type(value) is not str
                or not value
                or len(value) > 256
            ):
                return "typed_gate_reference_invalid"
    if (
        kind == MANAGED_CRYPTO_METAMORPHIC_ACTION_KIND
        and action.get("runtime") not in {"python", "sage"}
    ):
        return "typed_gate_action_invalid"
    if kind == MANAGED_REV_ACCEPTED_INPUT_ACTION_KIND:
        for field in (
            "operator_spec_sha256",
            "accepted_input_sha256",
        ):
            digest = action.get(field)
            if (
                type(digest) is not str
                or len(digest) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in digest
                )
            ):
                return "typed_gate_action_invalid"
        declared_argv = action.get("declared_argv")
        if (
            type(declared_argv) is not list
            or not 1 <= len(declared_argv) <= 16
            or any(
                type(argument) is not str
                or not argument
                or len(argument.encode("utf-8")) > 4096
                or "\x00" in argument
                for argument in declared_argv
            )
        ):
            return "typed_gate_action_invalid"
        try:
            validate_rev_acceptance_expected_oracle(
                action.get("expected_oracle")
            )
        except RevAcceptanceContractError:
            return "typed_gate_action_invalid"
    return None


class ManagedOrchestrator:
    """Serial durable managed orchestrator for exactly one selected challenge."""

    def __init__(
        self,
        engine: ChallengeEngine,
        *,
        capability_probe: CapabilityProbe = inspect_pinned_capabilities,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.engine = engine
        self.capability_probe = capability_probe
        self.wall_clock = wall_clock

    def preflight(
        self,
        identity: ChallengeIdentity,
        *,
        session_id: str | None = None,
        probe_image: bool = True,
    ) -> PreflightReport:
        state = self.engine.store.load(identity)
        issues: list[str] = []
        checks: dict[str, Any] = {}

        checks["state_schema"] = state.schema_version
        if state.schema_version != STATE_SCHEMA_VERSION:
            issues.append(
                "managed mode requires state schema v2; run migrate first"
            )
        checks["status"] = state.status.value
        if state.status in _STOP_STATUSES:
            issues.append(
                f"challenge status {state.status.value} blocks managed work"
            )
        checks["prompt_present"] = bool(state.prompt.strip())
        if not state.prompt.strip():
            issues.append("problem-solving prompt is required")

        checks["budget_mode"] = state.budget.mode.value
        if state.budget.mode is BudgetMode.LEGACY_UNARMED:
            issues.append(
                "legacy_unarmed budget requires an explicit bounded or "
                "operator-unbounded choice"
            )
        if (
            state.budget.mode is BudgetMode.OPERATOR_UNBOUNDED
            and not (state.budget.unbounded_reason or "").strip()
        ):
            issues.append("operator-unbounded budget requires a reason")
        try:
            self.engine._remaining_budget_seconds(state)
            checks["budget_available"] = True
        except EngineError as error:
            checks["budget_available"] = False
            issues.append(str(error))

        active = state.active_managed_session_id
        checks["active_managed_session_id"] = active
        if active is not None and session_id not in {None, active}:
            issues.append(
                f"managed session {active} is already active for this challenge"
            )

        remote_experiments = [
            item
            for item in state.experiments
            if (
                item.status is ExperimentStatus.REGISTERED
                and (
                    item.extra.get("network_target") is not None
                    or (
                        item.kind is ExperimentKind.PROOF
                        and item.proof_recipe is not None
                        and item.proof_recipe.network_endpoint is not None
                    )
                )
            )
        ]
        remote_pending = bool(remote_experiments)
        checks["remote_action_pending"] = remote_pending
        if remote_pending:
            primary = next(
                (
                    item
                    for item in state.targets
                    if item.id == state.primary_target_id
                ),
                None,
            )
            if primary is None:
                issues.append(
                    "managed remote work requires an explicitly selected target"
                )
            elif (
                primary.status is not TargetStatus.ACTIVE
                or self.engine._target_is_expired(primary)
            ):
                issues.append(
                    "selected target is revoked, expired, or inactive"
                )
            elif primary.enforcement not in {"proxy", "builtin"}:
                issues.append(
                    "managed remote work requires a destination-enforcing "
                    "proxy target"
                )
            else:
                for experiment in remote_experiments:
                    if (
                        experiment.kind is ExperimentKind.PROOF
                        and experiment.proof_recipe is not None
                    ):
                        recipe = experiment.proof_recipe
                        target_id = recipe.network_target_id
                        target_generation = (
                            recipe.network_target_generation
                        )
                        configuration_epoch = (
                            recipe.configuration_epoch
                        )
                        endpoint = recipe.network_endpoint
                    else:
                        target_id = experiment.extra.get(
                            "network_target_id"
                        )
                        target_generation = experiment.extra.get(
                            "network_target_generation"
                        )
                        configuration_epoch = experiment.extra.get(
                            "configuration_epoch"
                        )
                        endpoint = experiment.extra.get(
                            "network_target"
                        )
                    if (
                        target_id != primary.id
                        or target_generation != primary.generation
                        or configuration_epoch != state.configuration_epoch
                        or endpoint != primary.endpoint
                    ):
                        issues.append(
                            f"remote experiment {experiment.id} has a stale "
                            "target/generation/configuration pin"
                        )

        digest = self.engine.config.runtime.image_digest
        checks["image_digest"] = digest
        if digest is None:
            issues.append("managed mode requires a pinned runtime.image_digest")
        elif probe_image:
            category_issue: str | None = None
            try:
                if self.capability_probe is inspect_pinned_capabilities:
                    try:
                        required = (
                            required_managed_capabilities_for_category(
                                state.category
                            )
                        )
                    except CapabilityError as error:
                        category_issue = str(error)
                        capability = {
                            "ok": False,
                            "error": category_issue,
                        }
                    else:
                        capability = dict(
                            self.capability_probe(
                                digest,
                                required=required,
                            )
                        )
                else:
                    capability = dict(self.capability_probe(digest))
            except (CapabilityError, EngineError, OSError, ValueError) as error:
                capability = {"ok": False, "error": str(error)}
            checks["capabilities"] = capability
            if capability.get("ok") is not True:
                if category_issue is not None:
                    issues.append(category_issue)
                else:
                    missing = capability.get("missing")
                    suffix = (
                        ": " + ", ".join(str(item) for item in missing)
                        if isinstance(missing, list) and missing
                        else ""
                    )
                    issues.append(
                        "pinned image lacks managed capabilities" + suffix
                    )

        return PreflightReport(
            ok=not issues,
            identity=identity.key,
            state_revision=state.revision,
            configuration_epoch=state.configuration_epoch,
            checks=checks,
            issues=tuple(issues),
        )

    def require_preflight(
        self,
        identity: ChallengeIdentity,
        *,
        session_id: str | None = None,
        probe_image: bool = True,
    ) -> PreflightReport:
        report = self.preflight(
            identity,
            session_id=session_id,
            probe_image=probe_image,
        )
        if not report.ok:
            raise ManagedPreflightBlocked(report.issues)
        return report

    def _retire_stale_registered_managed_remote_actions(
        self,
        identity: ChallengeIdentity,
    ) -> ChallengeState:
        """Cancel stale model-owned remote work before managed preflight."""

        current = self.engine.store.load(identity)
        runs = {run.id: run for run in current.runs}

        def remote_binding(
            experiment: Experiment,
        ) -> tuple[object, object, object, object] | None:
            if (
                experiment.kind is ExperimentKind.PROOF
                and experiment.proof_recipe is not None
            ):
                recipe = experiment.proof_recipe
                if (
                    recipe.network_endpoint is None
                    and experiment.extra.get("network_target") is None
                ):
                    return None
                return (
                    recipe.network_target_id,
                    recipe.network_target_generation,
                    recipe.configuration_epoch,
                    recipe.network_endpoint,
                )
            endpoint = experiment.extra.get("network_target")
            if endpoint is None:
                return None
            return (
                experiment.extra.get("network_target_id"),
                experiment.extra.get("network_target_generation"),
                experiment.extra.get("configuration_epoch"),
                endpoint,
            )

        primary = next(
            (
                target
                for target in current.targets
                if target.id == current.primary_target_id
            ),
            None,
        )
        selected_binding = (
            (
                primary.id,
                primary.generation,
                current.configuration_epoch,
                primary.endpoint,
            )
            if (
                primary is not None
                and primary.status is TargetStatus.ACTIVE
                and not self.engine._target_is_expired(primary)
                and primary.enforcement in {"proxy", "builtin"}
            )
            else None
        )
        stale_ids = {
            experiment.id
            for experiment in current.experiments
            if (
                experiment.status is ExperimentStatus.REGISTERED
                and remote_binding(experiment) is not None
                and (
                    source_run := runs.get(experiment.source_run_id or "")
                )
                is not None
                and source_run.origin is RunOrigin.MANAGED_MODEL
                and remote_binding(experiment) != selected_binding
            )
        }
        if not stale_ids:
            return current

        def apply(state: ChallengeState) -> None:
            canonical_runs = {run.id: run for run in state.runs}
            canonical_primary = next(
                (
                    target
                    for target in state.targets
                    if target.id == state.primary_target_id
                ),
                None,
            )
            canonical_binding = (
                (
                    canonical_primary.id,
                    canonical_primary.generation,
                    state.configuration_epoch,
                    canonical_primary.endpoint,
                )
                if (
                    canonical_primary is not None
                    and canonical_primary.status is TargetStatus.ACTIVE
                    and not self.engine._target_is_expired(
                        canonical_primary
                    )
                    and canonical_primary.enforcement
                    in {"proxy", "builtin"}
                )
                else None
            )
            cancelled_at = utc_now()
            for experiment in state.experiments:
                source_run = canonical_runs.get(
                    experiment.source_run_id or ""
                )
                binding = remote_binding(experiment)
                if (
                    experiment.id in stale_ids
                    and experiment.status is ExperimentStatus.REGISTERED
                    and binding is not None
                    and source_run is not None
                    and source_run.origin is RunOrigin.MANAGED_MODEL
                    and binding != canonical_binding
                ):
                    experiment.status = ExperimentStatus.CANCELLED
                    experiment.extra["cancelled_at"] = cancelled_at
                    experiment.extra["cancelled_reason"] = (
                        "stale_managed_remote_binding_retired"
                    )

        return self.engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )

    @staticmethod
    def _session(state: ChallengeState, session_id: str) -> SolveSession:
        session = next(
            (item for item in state.sessions if item.id == session_id),
            None,
        )
        if session is None:
            raise ManagedError(f"unknown managed session: {session_id}")
        return session

    @staticmethod
    def _selected_target_binding(
        state: ChallengeState,
    ) -> tuple[str | None, int | None]:
        if state.primary_target_id is None:
            return None, None
        target = next(
            (
                item
                for item in state.targets
                if item.id == state.primary_target_id
            ),
            None,
        )
        if target is None:
            return None, None
        return target.id, target.generation

    def _expected_continuity_metadata(
        self,
        state: ChallengeState,
        policy: str,
    ) -> dict[str, Any]:
        try:
            selected_policy = validate_thread_continuity_policy(policy)
        except ManagedContinuityContractError as error:
            raise ManagedError(str(error)) from error
        target_id, target_generation = self._selected_target_binding(state)
        manifest = state.metadata.get("source_manifest_sha256")
        manifest_value = manifest if type(manifest) is str else None
        generation = source_generation(
            manifest_value,
            state.metadata.get("source_manifest_history"),
        )
        return build_session_metadata(
            policy=selected_policy,
            configuration_epoch=state.configuration_epoch,
            source_manifest_sha256=manifest_value,
            source_generation=generation,
            target_id=target_id,
            target_generation=target_generation,
            runtime_image_digest=self.engine.config.runtime.image_digest,
            captain_effort=self.engine.config.models.captain_effort,
            worker_effort=self.engine.config.models.worker_effort,
            models={
                role.value: self.engine._model_for_role(role)
                for role in Role
            },
        )

    @staticmethod
    def _continuity_metadata(
        session: SolveSession,
    ) -> dict[str, Any]:
        value = session.extra.get(THREAD_CONTINUITY_SESSION_KEY)
        issues = session_metadata_errors(value)
        if issues:
            raise ManagedError(
                "managed thread continuity session metadata is invalid: "
                + "; ".join(issues)
            )
        assert type(value) is dict
        return value

    @staticmethod
    def _continuity_fresh_reason(
        policy: str,
        role: Role,
        wave_kind: WaveKind | None,
    ) -> tuple[str, bool]:
        if wave_kind is WaveKind.PROOF:
            return "proof_wave_forced_fresh", False
        if policy == "fresh":
            return "policy_fresh", False
        if role.value in THREAD_CONTINUITY_ALWAYS_FRESH_ROLES:
            return (
                "captain_lane_non_captain"
                if policy == "captain_lane"
                else "role_lane_ineligible_role"
            ), False
        if policy == "captain_lane" and role is not Role.CAPTAIN:
            return "captain_lane_non_captain", False
        if (
            policy == "role_lane"
            and role.value not in THREAD_CONTINUITY_ELIGIBLE_ROLES
        ):
            return "role_lane_ineligible_role", False
        return "", True

    def _read_thread_secret(
        self,
        identity: ChallengeIdentity,
        run: RunReference,
    ) -> tuple[str | None, str]:
        expected_path = (
            self.engine.store.run_paths(identity, run_id=run.id).root
            / "thread-secret.json"
        )
        challenge_root = self.engine.store.challenge_paths(identity).root
        expected_pointer = expected_path.relative_to(
            challenge_root
        ).as_posix()
        if run.extra.get("thread_secret_path") != expected_pointer:
            return None, "prior_thread_missing"
        try:
            payload = read_json(expected_path)
        except (OSError, ValueError):
            return None, "prior_thread_missing"
        if (
            type(payload) is not dict
            or set(payload)
            != {
                "schema_version",
                "run_id",
                "thread_id",
                "thread_id_sha256",
            }
            or payload.get("schema_version") != 1
            or payload.get("run_id") != run.id
        ):
            return None, "prior_thread_invalid"
        thread_id = payload.get("thread_id")
        if not valid_thread_id(thread_id):
            return None, "prior_thread_invalid"
        digest = thread_id_sha256(thread_id)
        if (
            payload.get("thread_id_sha256") != digest
            or run.extra.get("produced_thread_id_sha256") != digest
        ):
            return None, "prior_thread_hash_mismatch"
        return thread_id, ""

    def _build_continuity_audit(
        self,
        state: ChallengeState,
        session: SolveSession,
        *,
        identity: ChallengeIdentity,
        run_id: str,
        role: Role,
        wave_kind: WaveKind | None,
    ) -> tuple[dict[str, Any], str | None]:
        metadata = self._continuity_metadata(session)
        policy = str(metadata["policy"])
        reason, eligible = self._continuity_fresh_reason(
            policy,
            role,
            wave_kind,
        )
        model = self.engine._model_for_role(role)
        lane_identity: str | None = None
        if eligible:
            lane_identity = build_lane_identity(
                session_id=session.id,
                configuration_fingerprint_sha256=str(
                    metadata["configuration_fingerprint_sha256"]
                ),
                configuration_epoch=state.configuration_epoch,
                role=role.value,
                model=model,
                source_manifest_sha256=(
                    metadata["source_manifest_sha256"]
                    if type(metadata["source_manifest_sha256"]) is str
                    else None
                ),
                source_generation=int(metadata["source_generation"]),
                target_id=(
                    metadata["target_id"]
                    if type(metadata["target_id"]) is str
                    else None
                ),
                target_generation=(
                    metadata["target_generation"]
                    if type(metadata["target_generation"]) is int
                    else None
                ),
            )
        if not eligible:
            return (
                build_run_audit(
                    session_metadata=metadata,
                    session_id=session.id,
                    role=role.value,
                    model=model,
                    decision="fresh",
                    reason=reason,
                    source_run_id=None,
                    source_thread_id_sha256=None,
                    stable_lane=False,
                    lane_identity_sha256=None,
                    workspace_owner_run_id=None,
                ),
                None,
            )

        run_index = {item.id: item for item in state.runs}
        prior: RunReference | None = None
        for prior_run_id in reversed(session.run_ids):
            candidate = run_index.get(prior_run_id)
            if (
                candidate is not None
                and candidate.origin is RunOrigin.MANAGED_MODEL
                and candidate.role == role.value
            ):
                prior = candidate
                break
        if prior is None:
            return (
                build_run_audit(
                    session_metadata=metadata,
                    session_id=session.id,
                    role=role.value,
                    model=model,
                    decision="fresh",
                    reason="no_prior_lane_run",
                    source_run_id=None,
                    source_thread_id_sha256=None,
                    stable_lane=True,
                    lane_identity_sha256=lane_identity,
                    workspace_owner_run_id=run_id,
                ),
                None,
            )

        mismatch_reason: str | None = None
        if prior.status is not RunStatus.COMPLETED:
            mismatch_reason = "prior_lane_not_completed"
        elif prior.session_id != session.id:
            mismatch_reason = "prior_session_mismatch"
        elif prior.configuration_epoch != state.configuration_epoch:
            mismatch_reason = "prior_configuration_mismatch"
        elif prior.model != model:
            mismatch_reason = "prior_model_mismatch"
        elif (
            prior.extra.get("contract_version")
            != THREAD_CONTINUITY_CONTRACT_VERSION
        ):
            mismatch_reason = "prior_contract_mismatch"
        elif prior.role != role.value:
            mismatch_reason = "prior_role_mismatch"
        prior_audit = prior.extra.get(THREAD_CONTINUITY_RUN_KEY)
        if mismatch_reason is None:
            prior_issues = run_audit_errors(prior_audit)
            if prior_issues:
                mismatch_reason = "prior_workspace_mismatch"
        if mismatch_reason is None:
            assert type(prior_audit) is dict
            expected_pairs = (
                ("session_id", session.id, "prior_session_mismatch"),
                (
                    "configuration_epoch",
                    state.configuration_epoch,
                    "prior_configuration_mismatch",
                ),
                (
                    "configuration_fingerprint_sha256",
                    metadata["configuration_fingerprint_sha256"],
                    "prior_configuration_mismatch",
                ),
                (
                    "contract_version",
                    THREAD_CONTINUITY_CONTRACT_VERSION,
                    "prior_contract_mismatch",
                ),
                ("logical_role", role.value, "prior_role_mismatch"),
                ("model", model, "prior_model_mismatch"),
                (
                    "lane_identity_sha256",
                    lane_identity,
                    "prior_workspace_mismatch",
                ),
                (
                    "source_manifest_sha256",
                    metadata["source_manifest_sha256"],
                    "prior_source_mismatch",
                ),
                (
                    "source_generation",
                    metadata["source_generation"],
                    "prior_source_mismatch",
                ),
                ("target_id", metadata["target_id"], "prior_target_mismatch"),
                (
                    "target_generation",
                    metadata["target_generation"],
                    "prior_target_mismatch",
                ),
            )
            for key, expected, issue in expected_pairs:
                if prior_audit.get(key) != expected:
                    mismatch_reason = issue
                    break
            if prior_audit.get("stable_lane") is not True:
                mismatch_reason = "prior_workspace_mismatch"
        resume_thread: str | None = None
        if mismatch_reason is None:
            resume_thread, mismatch_reason = self._read_thread_secret(
                identity,
                prior,
            )
            mismatch_reason = mismatch_reason or None
        if mismatch_reason is not None:
            return (
                build_run_audit(
                    session_metadata=metadata,
                    session_id=session.id,
                    role=role.value,
                    model=model,
                    decision="fresh",
                    reason=mismatch_reason,
                    source_run_id=None,
                    source_thread_id_sha256=None,
                    stable_lane=False,
                    lane_identity_sha256=None,
                    workspace_owner_run_id=None,
                ),
                None,
            )
        assert resume_thread is not None
        assert type(prior_audit) is dict
        return (
            build_run_audit(
                session_metadata=metadata,
                session_id=session.id,
                role=role.value,
                model=model,
                decision="resume",
                reason="resume_previous_completed_lane",
                source_run_id=prior.id,
                source_thread_id_sha256=thread_id_sha256(resume_thread),
                stable_lane=True,
                lane_identity_sha256=lane_identity,
                workspace_owner_run_id=str(
                    prior_audit["workspace_owner_run_id"]
                ),
            ),
            resume_thread,
        )

    def _resume_thread_for_reserved_run(
        self,
        identity: ChallengeIdentity,
        run_id: str,
    ) -> str | None:
        state = self.engine.store.load(identity)
        run = next(
            (item for item in state.runs if item.id == run_id),
            None,
        )
        if run is None or run.status is not RunStatus.CREATED:
            raise ManagedError(
                f"managed continuity run is not reserved: {run_id}"
            )
        audit = run.extra.get(THREAD_CONTINUITY_RUN_KEY)
        issues = run_audit_errors(audit)
        if issues:
            raise ManagedError(
                "managed continuity run audit is invalid: "
                + "; ".join(issues)
            )
        assert type(audit) is dict
        if audit["decision"] == "fresh":
            return None
        source_run = next(
            (
                item
                for item in state.runs
                if item.id == audit["source_run_id"]
            ),
            None,
        )
        if source_run is None:
            raise ManagedError("managed continuity source run disappeared")
        thread_id, reason = self._read_thread_secret(identity, source_run)
        if (
            thread_id is None
            or reason
            or thread_id_sha256(thread_id) != audit["thread_id_sha256"]
        ):
            raise ManagedError(
                "managed continuity source thread changed after reservation"
            )
        return thread_id

    def _reserve_session(
        self,
        identity: ChallengeIdentity,
        session_id: str | None,
        *,
        thread_continuity_policy: str = "fresh",
    ) -> tuple[ChallengeState, str]:
        current = self.engine.store.load(identity)
        expected_continuity = self._expected_continuity_metadata(
            current,
            thread_continuity_policy,
        )
        selected = (
            session_id
            or current.active_managed_session_id
            or f"S-{uuid.uuid4().hex}"
        )
        existing_session = next(
            (item for item in current.sessions if item.id == selected),
            None,
        )
        if current.metadata.get("evaluation_prepared") is True:
            try:
                command_contract_sha256 = managed_command_contract_sha256(
                    model_id=self.engine.config.models.captain,
                    captain_effort=(
                        self.engine.config.models.captain_effort
                    ),
                    worker_effort=(
                        self.engine.config.models.worker_effort
                    ),
                    thread_continuity_policy=(
                        thread_continuity_policy
                    ),
                )
            except ScaffoldBindingError as error:
                raise ManagedError(
                    f"managed evaluation scaffold contract is invalid: {error}"
                ) from error
            if existing_session is None:
                if current.active_managed_session_id not in {
                    None,
                    selected,
                }:
                    raise ManagedError(
                        "another managed session is active for this challenge"
                    )
                current = self.engine.record_evaluation_scaffold_launch(
                    identity,
                    arm=CTF_OS_SYSTEM,
                    command_contract_sha256=command_contract_sha256,
                )
            launch_record = current.metadata.get(
                SCAFFOLD_LAUNCH_METADATA_KEY
            )
            try:
                validate_scaffold_launch_record(
                    metadata=current.metadata,
                    configuration_epoch=current.configuration_epoch,
                    contest_id=identity.contest_id,
                    category=identity.category,
                    challenge_id=identity.challenge_id,
                    value=launch_record,
                    expected_arm=CTF_OS_SYSTEM,
                    expected_command_contract_sha256=(
                        command_contract_sha256
                    ),
                )
            except ScaffoldBindingError as error:
                raise ManagedError(
                    "managed evaluation scaffold launch is invalid: "
                    f"{error}"
                ) from error
            expected_continuity = self._expected_continuity_metadata(
                current,
                thread_continuity_policy,
            )

        def apply(state: ChallengeState) -> None:
            if state.configuration_epoch != current.configuration_epoch:
                raise ManagedError("configuration changed during session reserve")
            if state.active_managed_session_id not in {None, selected}:
                raise ManagedError(
                    "another managed session is active for this challenge"
                )
            session = next(
                (item for item in state.sessions if item.id == selected),
                None,
            )
            if session is None:
                session = SolveSession(
                    id=selected,
                    mode=SessionMode.MANAGED,
                    status=SessionStatus.RUNNING,
                    configuration_epoch=state.configuration_epoch,
                    start_revision=state.revision,
                    budget_snapshot=state.budget.to_dict(v2=True),
                    evaluation_policy="observe",
                    started_at=utc_now(),
                )
                session.extra[THREAD_CONTINUITY_SESSION_KEY] = (
                    expected_continuity
                )
                state.sessions.append(session)
            elif (
                session.mode is not SessionMode.MANAGED
                or session.status not in {
                    SessionStatus.CREATED,
                    SessionStatus.RUNNING,
                }
            ):
                raise ManagedError(
                    f"session {selected} cannot be resumed from "
                    f"{session.status.value}"
                )
            elif session.configuration_epoch != state.configuration_epoch:
                raise ManagedError(
                    "session configuration epoch is stale; start a new session"
                )
            existing_continuity = session.extra.get(
                THREAD_CONTINUITY_SESSION_KEY
            )
            if existing_continuity is None:
                if session.run_ids or session.wave_ids:
                    raise ManagedError(
                        "thread continuity metadata must be pinned before "
                        "managed session work starts; start a new session"
                    )
                session.extra[THREAD_CONTINUITY_SESSION_KEY] = (
                    expected_continuity
                )
            elif session_metadata_errors(existing_continuity):
                raise ManagedError(
                    "managed thread continuity metadata is invalid"
                )
            elif existing_continuity != expected_continuity:
                raise ManagedError(
                    "managed thread continuity policy/configuration is pinned "
                    "for the session; start a new session"
                )
            session.status = SessionStatus.RUNNING
            session.started_at = session.started_at or utc_now()
            state.active_managed_session_id = selected

        return (
            self.engine.store.update(
                identity,
                apply,
                expected_revision=current.revision,
            ),
            selected,
        )

    def _require_epoch(
        self,
        state: ChallengeState,
        session_id: str,
    ) -> SolveSession:
        session = self._session(state, session_id)
        if state.active_managed_session_id != session_id:
            raise ManagedError("managed session is no longer active")
        if session.configuration_epoch != state.configuration_epoch:
            raise ManagedError(
                "configuration epoch changed during managed execution"
            )
        return session

    def _reserve_cycle(
        self,
        identity: ChallengeIdentity,
        session_id: str,
    ) -> tuple[ChallengeState, ManagedCycle]:
        current = self.engine.store.load(identity)
        self._require_epoch(current, session_id)
        ordinal = 1 + max(
            (
                item.ordinal
                for item in current.cycles
                if item.session_id == session_id
            ),
            default=0,
        )
        cycle_id = _stable_id("MC", identity.key, session_id, ordinal)
        run_id = _stable_id(
            "MR",
            identity.key,
            session_id,
            cycle_id,
            "captain",
            current.configuration_epoch,
        )
        current_session = self._session(current, session_id)
        continuity_audit, _resume_thread = self._build_continuity_audit(
            current,
            current_session,
            identity=identity,
            run_id=run_id,
            role=Role.CAPTAIN,
            wave_kind=None,
        )

        def apply(state: ChallengeState) -> None:
            session = self._require_epoch(state, session_id)
            if any(item.id == cycle_id for item in state.cycles):
                raise ManagedError(f"managed cycle already exists: {cycle_id}")
            anticipated_revision = state.revision + 1
            cycle = ManagedCycle(
                id=cycle_id,
                session_id=session_id,
                ordinal=ordinal,
                phase="captain_reserved",
                configuration_epoch=state.configuration_epoch,
                captain_run_id=run_id,
            )
            state.cycles.append(cycle)
            state.runs.append(
                RunReference(
                    id=run_id,
                    base_revision=anticipated_revision,
                    status=RunStatus.CREATED,
                    role=Role.CAPTAIN.value,
                    model=self.engine._model_for_role(Role.CAPTAIN),
                    origin=RunOrigin.MANAGED_MODEL,
                    idempotency_key=(
                        f"managed:{identity.key}:{session_id}:{ordinal}:"
                        f"captain:{state.configuration_epoch}"
                    ),
                    session_id=session_id,
                    cycle_id=cycle_id,
                    configuration_epoch=state.configuration_epoch,
                    extra={
                        "contract_version": (
                            THREAD_CONTINUITY_CONTRACT_VERSION
                        ),
                        THREAD_CONTINUITY_RUN_KEY: continuity_audit,
                    },
                )
            )
            session.run_ids.append(run_id)

        committed = self.engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )
        return committed, next(
            item for item in committed.cycles if item.id == cycle_id
        )

    def _rebase_created_run(
        self,
        identity: ChallengeIdentity,
        session_id: str,
        run_id: str,
    ) -> ChallengeState:
        """Move an undispatched reservation to the latest durable snapshot."""

        current = self.engine.store.load(identity)

        def apply(state: ChallengeState) -> None:
            self._require_epoch(state, session_id)
            run = next(
                (item for item in state.runs if item.id == run_id),
                None,
            )
            if run is None or run.status is not RunStatus.CREATED:
                raise ManagedError(
                    f"managed run is not an undispatched reservation: {run_id}"
                )
            run.base_revision = state.revision + 1

        return self.engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )

    def _managed_wave_budget_guard(
        self,
        state: ChallengeState,
        wave_name: str,
    ) -> dict[str, object]:
        """Decide admission from one provider and one finite clock sample."""

        try:
            provider_snapshot = self.engine.batch_runner.limiter.snapshot()
            snapshot_capacity = provider_snapshot.capacity
            snapshot_active = provider_snapshot.active
            snapshot_waiting = provider_snapshot.waiting
        except Exception as error:
            raise ManagedError(
                "managed wave provider snapshot failed"
            ) from error

        # Sample the budget only after snapshot acquisition, so time blocked
        # on a shared limiter lock can never make the remainder optimistic.
        try:
            now_epoch = self.wall_clock()
        except Exception as error:
            raise ManagedError(
                "managed wave budget clock failed"
            ) from error
        if (
            isinstance(now_epoch, bool)
            or not isinstance(now_epoch, (int, float))
            or not math.isfinite(float(now_epoch))
        ):
            raise ManagedError("managed wave budget clock must be finite")
        try:
            remaining = budget_remaining_seconds(
                state.budget,
                now_epoch=float(now_epoch),
            )
            runtime = self.engine.config.runtime
            return build_managed_wave_budget_guard_v2(
                wave_kind=wave_name,
                provider_max_concurrent_calls=(
                    self.engine.config.resources
                    .provider_max_concurrent_calls
                ),
                provider_snapshot_capacity=snapshot_capacity,
                provider_snapshot_active=snapshot_active,
                provider_snapshot_waiting=snapshot_waiting,
                queue_reserve_seconds=(
                    runtime.managed_wave_queue_reserve_s
                ),
                role_call_reserve_seconds=(
                    runtime.managed_wave_role_call_reserve_s
                ),
                action_commit_reserve_seconds=(
                    runtime.managed_wave_action_commit_reserve_s
                ),
                remaining_seconds=remaining,
                checked_state_revision=state.revision,
                configuration_epoch=state.configuration_epoch,
                budget_mode=state.budget.mode.value,
            )
        except (
            BudgetExhausted,
            ManagedWaveBudgetContractError,
            OverflowError,
            TypeError,
            ValueError,
        ) as error:
            raise ManagedError(
                f"managed wave budget guard is invalid: {error}"
            ) from error

    def _reserve_wave(
        self,
        identity: ChallengeIdentity,
        session_id: str,
        cycle_id: str,
        wave_name: str,
        *,
        enforce_budget_guard: bool = False,
    ) -> tuple[ChallengeState, ManagedWave, dict[Role, str]]:
        roles = WAVE_ROLES[wave_name]
        kind = WaveKind(wave_name)
        current = self.engine.store.load(identity)
        self._require_epoch(current, session_id)
        budget_audit = (
            self._managed_wave_budget_guard(current, wave_name)
            if enforce_budget_guard
            else None
        )
        if (
            budget_audit is not None
            and budget_audit["decision"] == "pause"
        ):
            def apply_budget_pause(state: ChallengeState) -> None:
                self._require_epoch(state, session_id)
                cycle = next(
                    (
                        item
                        for item in state.cycles
                        if item.id == cycle_id
                    ),
                    None,
                )
                if cycle is None:
                    raise ManagedError(
                        f"unknown managed cycle: {cycle_id}"
                    )
                if cycle.wave_id is not None:
                    raise ManagedError(
                        f"cycle {cycle_id} already has wave "
                        f"{cycle.wave_id}"
                    )
                if any(
                    key in cycle.extra
                    for key in (
                        MANAGED_WAVE_BUDGET_GUARD_KEY,
                        MANAGED_WAVE_BUDGET_GUARD_V2_KEY,
                    )
                ):
                    raise ManagedError(
                        "managed wave budget guard is already recorded"
                    )
                cycle.extra[MANAGED_WAVE_BUDGET_GUARD_V2_KEY] = (
                    dict(budget_audit)
                )
                cycle.phase = "wave_budget_blocked"

            committed = self.engine.store.update(
                identity,
                apply_budget_pause,
                expected_revision=current.revision,
            )
            raise ManagedWaveBudgetInsufficient(
                committed,
                budget_audit,
            )
        wave_id = _stable_id(
            "MW",
            identity.key,
            session_id,
            cycle_id,
            wave_name,
            current.configuration_epoch,
        )
        role_runs = {
            role: _stable_id(
                "MR",
                identity.key,
                session_id,
                cycle_id,
                wave_id,
                role.value,
                current.configuration_epoch,
            )
            for role in roles
        }
        current_session = self._session(current, session_id)
        continuity_audits = {
            role: self._build_continuity_audit(
                current,
                current_session,
                identity=identity,
                run_id=role_runs[role],
                role=role,
                wave_kind=kind,
            )[0]
            for role in roles
        }

        def apply(state: ChallengeState) -> None:
            session = self._require_epoch(state, session_id)
            cycle = next(
                (item for item in state.cycles if item.id == cycle_id),
                None,
            )
            if cycle is None:
                raise ManagedError(f"unknown managed cycle: {cycle_id}")
            if cycle.wave_id is not None:
                raise ManagedError(
                    f"cycle {cycle_id} already has wave {cycle.wave_id}"
                )
            if budget_audit is not None:
                if any(
                    key in cycle.extra
                    for key in (
                        MANAGED_WAVE_BUDGET_GUARD_KEY,
                        MANAGED_WAVE_BUDGET_GUARD_V2_KEY,
                    )
                ):
                    raise ManagedError(
                        "managed wave budget guard is already recorded"
                    )
                cycle.extra[MANAGED_WAVE_BUDGET_GUARD_V2_KEY] = dict(
                    budget_audit
                )
            anticipated_revision = state.revision + 1
            wave = ManagedWave(
                id=wave_id,
                session_id=session_id,
                cycle_id=cycle_id,
                kind=kind,
                role_run_ids={
                    role.value: role_runs[role] for role in roles
                },
                snapshot_revision=anticipated_revision,
                configuration_epoch=state.configuration_epoch,
                status="created",
            )
            state.waves.append(wave)
            cycle.wave_id = wave_id
            cycle.phase = "wave_reserved"
            session.wave_ids.append(wave_id)
            for role in roles:
                run_id = role_runs[role]
                state.runs.append(
                    RunReference(
                        id=run_id,
                        base_revision=anticipated_revision,
                        status=RunStatus.CREATED,
                        role=role.value,
                        model=self.engine._model_for_role(role),
                        origin=RunOrigin.MANAGED_MODEL,
                        idempotency_key=(
                            f"managed:{identity.key}:{session_id}:"
                            f"{cycle_id}:{wave_name}:{role.value}:"
                            f"{state.configuration_epoch}"
                        ),
                        session_id=session_id,
                        cycle_id=cycle_id,
                        wave_id=wave_id,
                        configuration_epoch=state.configuration_epoch,
                        extra={
                            "contract_version": (
                                THREAD_CONTINUITY_CONTRACT_VERSION
                            ),
                            THREAD_CONTINUITY_RUN_KEY: (
                                continuity_audits[role]
                            ),
                        },
                    )
                )
                session.run_ids.append(run_id)

        committed = self.engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )
        return (
            committed,
            next(item for item in committed.waves if item.id == wave_id),
            role_runs,
        )

    @staticmethod
    def _wave_name(captain_output: Mapping[str, object] | None) -> str:
        decision = (
            captain_output.get("decision")
            if isinstance(captain_output, Mapping)
            else None
        )
        next_stage = (
            str(decision.get("next_stage"))
            if isinstance(decision, Mapping)
            else "discover"
        )
        wave = {
            "discover": "discovery",
            "attack": "attack",
            "proof": "proof",
        }.get(next_stage)
        if wave is None:
            raise ManagedError(
                f"Captain did not select a runnable stage: {next_stage}"
            )
        return wave

    @staticmethod
    def _captain_registered_experiment_reference(
        captain_output: Mapping[str, object] | None,
    ) -> Mapping[str, object] | None:
        decision = (
            captain_output.get("decision")
            if isinstance(captain_output, Mapping)
            else None
        )
        if not isinstance(decision, Mapping):
            return None
        reference = decision.get("selected_experiment")
        if reference is None:
            return None
        if not isinstance(reference, Mapping):
            raise ManagedRegisteredExperimentReferenceError(
                "Captain selected_experiment is not a canonical object"
            )
        return reference

    @staticmethod
    def _validate_registered_experiment_reference(
        state: ChallengeState,
        reference: Mapping[str, object],
        *,
        next_stage: str | None = None,
    ) -> Experiment:
        expected_keys = {
            "experiment_id",
            "command_sha256",
            "contract_sha256",
        }
        if set(reference) != expected_keys:
            raise ManagedRegisteredExperimentReferenceError(
                "Captain selected_experiment has invalid fields"
            )
        experiment_id = reference.get("experiment_id")
        if not isinstance(experiment_id, str):
            raise ManagedRegisteredExperimentReferenceError(
                "Captain selected_experiment has an invalid experiment_id"
            )
        experiment = next(
            (
                item
                for item in state.experiments
                if item.id == experiment_id
            ),
            None,
        )
        if experiment is None:
            raise ManagedRegisteredExperimentReferenceError(
                f"Captain selected unknown experiment: {experiment_id}"
            )
        if experiment.status is not ExperimentStatus.REGISTERED:
            raise ManagedRegisteredExperimentReferenceError(
                f"Captain selected non-REGISTERED experiment: {experiment_id}"
            )
        source_run = next(
            (
                item
                for item in state.runs
                if item.id == experiment.source_run_id
            ),
            None,
        )
        managed_contract_version = experiment.extra.get(
            "managed_contract_version"
        )
        source_contract_version = (
            source_run.extra.get("contract_version")
            if source_run is not None
            else None
        )
        ordinary_managed_command = (
            source_run is not None
            and source_run.origin is RunOrigin.MANAGED_MODEL
            and source_run.status is RunStatus.COMPLETED
            and type(source_contract_version) is int
            and source_contract_version == 2
            and source_run.extra.get("semantic_merge") is True
            and type(managed_contract_version) is int
            and managed_contract_version == 2
            and experiment.extra.get("managed_command_protocol")
            == MANAGED_SHELL_COMMAND_PROTOCOL
            and experiment.extra.get("engine_executor") is None
            and experiment.extra.get("adapter_seed") is None
            and experiment.proof_recipe is None
            and experiment.kind is not ExperimentKind.PROOF
        )
        if not ordinary_managed_command:
            raise ManagedRegisteredExperimentReferenceError(
                "Captain selected_experiment is not an ordinary v2 managed "
                "command"
            )
        if next_stage == "proof":
            raise ManagedRegisteredExperimentReferenceError(
                "Captain cannot route an ordinary registered command through "
                "the strict proof wave"
            )
        if not managed_registered_contract_is_bounded(experiment):
            raise ManagedRegisteredExperimentReferenceError(
                "Captain selected_experiment contract exceeds the bounded "
                "worker projection"
            )
        try:
            expected_binding = managed_registered_selection_binding(
                experiment
            )
        except (ModelValidationError, UnicodeError) as error:
            raise ManagedRegisteredExperimentReferenceError(
                "Captain selected_experiment is not valid UTF-8"
            ) from error
        for field in ("command_sha256", "contract_sha256"):
            if reference.get(field) != expected_binding[field]:
                raise ManagedRegisteredExperimentReferenceError(
                    f"Captain selected_experiment {field} mismatch"
                )
        return experiment

    def _bind_captain_registered_experiment(
        self,
        identity: ChallengeIdentity,
        session_id: str,
        cycle_id: str,
        captain_output: Mapping[str, object] | None,
        *,
        next_stage: str,
    ) -> ChallengeState:
        reference = self._captain_registered_experiment_reference(
            captain_output
        )
        current = self.engine.store.load(identity)
        if reference is None:
            return current
        self._validate_registered_experiment_reference(
            current,
            reference,
            next_stage=next_stage,
        )

        def apply(state: ChallengeState) -> None:
            self._require_epoch(state, session_id)
            experiment = self._validate_registered_experiment_reference(
                state,
                reference,
                next_stage=next_stage,
            )
            cycle = next(
                item for item in state.cycles if item.id == cycle_id
            )
            if MANAGED_REGISTERED_SELECTION_KEY in cycle.extra:
                raise ManagedRegisteredExperimentReferenceError(
                    "Captain registered selection is already bound"
                )
            cycle.extra[MANAGED_REGISTERED_SELECTION_KEY] = (
                managed_registered_selection_binding(experiment)
            )
            cycle.selected_action_ids = list(
                dict.fromkeys(
                    (*cycle.selected_action_ids, experiment.id)
                )
            )
            cycle.phase = "action_selected"

        return self.engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )

    @staticmethod
    def _bound_registered_experiment_id(
        state: ChallengeState,
        cycle: ManagedCycle | None,
    ) -> str | None:
        if cycle is None:
            return None
        binding = cycle.extra.get(MANAGED_REGISTERED_SELECTION_KEY)
        if binding is None:
            return None
        if not isinstance(binding, Mapping):
            raise ManagedRegisteredExperimentReferenceError(
                "cycle registered selection binding is not canonical"
            )
        reference = {
            key: binding.get(key)
            for key in (
                "experiment_id",
                "command_sha256",
                "contract_sha256",
            )
        }
        experiment = ManagedOrchestrator._validate_registered_experiment_reference(
            state,
            reference,
        )
        if not managed_registered_selection_matches(experiment, binding):
            raise ManagedRegisteredExperimentReferenceError(
                "cycle registered selection binding changed"
            )
        if experiment.id not in cycle.selected_action_ids:
            raise ManagedRegisteredExperimentReferenceError(
                "cycle registered selection is not selected"
            )
        return experiment.id

    @staticmethod
    def _frontier_routing_issue(
        state: ChallengeState,
        captain_output: Mapping[str, object] | None,
    ) -> str | None:
        decision = (
            captain_output.get("decision")
            if isinstance(captain_output, Mapping)
            else None
        )
        next_stage = (
            str(decision.get("next_stage"))
            if isinstance(decision, Mapping)
            else None
        )
        if next_stage not in {"attack", "proof"}:
            return None
        complete = distinct_complete_active_hypotheses(
            state.hypotheses
        )
        if len(complete) >= 3:
            return None
        return (
            f"Captain selected {next_stage} with only {len(complete)} "
            "distinct complete active hypotheses; at least 3 are required "
            "with evidence, non-empty unknowns, experiment, "
            "success_oracle, and falsifier"
        )

    @staticmethod
    def _discovery_execution_fingerprint(
        experiment: Experiment,
    ) -> bytes:
        """Project one role proposal onto its exact semantic execution.

        Source-run provenance is intentionally absent, while every durable
        field that can change either its hypothesis evaluation or sandbox
        request is retained. Treat the full extra mapping and artifact
        bindings as opaque exact values so a future execution-affecting field
        fails safe by preventing deduplication.
        """

        return canonical_json_bytes(
            {
                "schema_version": 1,
                "kind": experiment.kind.value,
                "hypothesis_ids": sorted(experiment.hypothesis_ids),
                "command": experiment.command,
                "expected_observation": experiment.expected_observation,
                "keep_if": experiment.keep_if,
                "drop_if": experiment.drop_if,
                "timeout_seconds": experiment.timeout_seconds,
                "resource_class": experiment.resource_class,
                "artifact_ids": list(experiment.artifact_ids),
                "execution_metadata": experiment.extra,
            }
        )

    @staticmethod
    def _select_actions(
        state: ChallengeState,
        wave: ManagedWave,
    ) -> tuple[str, ...]:
        cycle = next(
            (
                item
                for item in state.cycles
                if item.id == wave.cycle_id
            ),
            None,
        )
        bound_registered_id = (
            ManagedOrchestrator._bound_registered_experiment_id(
                state,
                cycle,
            )
        )
        if bound_registered_id is not None:
            # An explicit, hash-bound Captain reference is exclusive.  It is
            # not part of the current-run candidate reducer and must never be
            # duplicated as a freshly registered command.
            return (bound_registered_id,)
        role_order = {
            run_id: index + 1
            for index, run_id in enumerate(wave.role_run_ids.values())
        }
        if cycle is not None:
            role_order[cycle.captain_run_id] = 0
        candidates = [
            item
            for item in state.experiments
            if item.status is ExperimentStatus.REGISTERED
            and item.source_run_id in role_order
        ]
        typed_gates = [
            item
            for item in candidates
            if item.extra.get("engine_executor")
            == _MANAGED_TYPED_GATE_ENGINE_EXECUTOR
        ]
        if typed_gates:
            typed_gates.sort(key=lambda item: item.id)
            if len(typed_gates) != 1:
                raise ManagedError(
                    "managed wave must contain at most one typed category gate"
                )
            return (typed_gates[0].id,)
        if wave.kind is WaveKind.PROOF:
            reproducer_run_id = wave.role_run_ids.get("reproducer")
            proof_recipes = [
                item
                for item in candidates
                if item.kind is ExperimentKind.PROOF
                and item.proof_recipe is not None
                and item.source_run_id == reproducer_run_id
            ]
            proof_recipes.sort(key=lambda item: item.id)
            if len(proof_recipes) != 1 or len(candidates) != 1:
                raise ManagedError(
                    "proof wave must produce exactly one registered proof "
                    "recipe and no other actions; observed "
                    f"{len(proof_recipes)} recipe(s) and "
                    f"{len(candidates)} total action(s)"
                )
            return (proof_recipes[0].id,)
        open_hypotheses = {
            item.id
            for item in state.hypotheses
            if item.status in ACTIVE_HYPOTHESIS_STATUSES
        }
        strategic = [
            item
            for item in candidates
            if item.kind is ExperimentKind.STRATEGIC
            and item.hypothesis_ids
            and set(item.hypothesis_ids) <= open_hypotheses
            and item.expected_observation.strip()
            and item.keep_if.strip()
            and item.drop_if.strip()
        ]
        if strategic:
            builder_run_id = wave.role_run_ids.get(Role.BUILDER.value)

            def bound_builder_priority(item: Experiment) -> int:
                """Prefer an executable Builder publication over timeout."""

                binding = item.extra.get("managed_action_input_binding")
                is_current_bound_builder = (
                    item.source_run_id == builder_run_id
                    and item.extra.get("managed_command_protocol")
                    == MANAGED_SHELL_COMMAND_PROTOCOL
                    and isinstance(binding, Mapping)
                    and binding.get("protocol")
                    == "same_run_publications_v1"
                    and binding.get("source_run_id") == builder_run_id
                    and isinstance(binding.get("artifacts"), list)
                    and bool(binding["artifacts"])
                )
                return 0 if is_current_bound_builder else 1

            strategic.sort(
                key=lambda item: (
                    -len(set(item.hypothesis_ids) & open_hypotheses),
                    bound_builder_priority(item),
                    item.timeout_seconds,
                    role_order.get(item.source_run_id or "", 999),
                    item.id,
                )
            )
        probes = [
            item
            for item in candidates
            if item.kind is ExperimentKind.PROBE
            and not item.hypothesis_ids
        ]
        probes.sort(
            key=lambda item: (
                role_order.get(item.source_run_id or "", 999),
                item.id,
            )
        )
        selected: list[str] = []
        discovery_executions: set[bytes] = set()
        role_approaches: set[tuple[str, str]] = set()
        for item in (*strategic, *probes):
            approach = (item.source_run_id or "", item.command)
            if wave.kind is WaveKind.DISCOVERY:
                execution = (
                    ManagedOrchestrator._discovery_execution_fingerprint(
                        item
                    )
                )
                if execution in discovery_executions:
                    continue
                if approach in role_approaches:
                    continue
                # Only selected proposals consume either uniqueness key. A
                # cross-role duplicate must not suppress a later, semantically
                # distinct proposal from that duplicate's role.
                discovery_executions.add(execution)
                role_approaches.add(approach)
            else:
                # ATTACK retains independent cross-role reproduction, and
                # PROOF has already returned through its strict recipe path.
                if approach in role_approaches:
                    continue
                role_approaches.add(approach)
            selected.append(item.id)
            if len(selected) == 3:
                break
        return tuple(selected)

    @staticmethod
    def _initial_cartography_actions(
        state: ChallengeState,
        *,
        maximum: int = 3,
    ) -> tuple[str, ...]:
        return tuple(
            item.id
            for item in state.experiments
            if item.status is ExperimentStatus.REGISTERED
            and item.extra.get("adapter_seed") is True
        )[:maximum]

    def _mark_action_selection(
        self,
        identity: ChallengeIdentity,
        session_id: str,
        cycle_id: str,
        selected: Sequence[str],
        *,
        append: bool = False,
    ) -> ChallengeState:
        current = self.engine.store.load(identity)

        def apply(state: ChallengeState) -> None:
            self._require_epoch(state, session_id)
            cycle = next(item for item in state.cycles if item.id == cycle_id)
            cycle.selected_action_ids = (
                list(
                    dict.fromkeys(
                        (*cycle.selected_action_ids, *selected)
                    )
                )
                if append
                else list(selected)
            )
            cycle.phase = (
                "action_selected"
                if cycle.selected_action_ids
                else "no_action_selected"
            )

        return self.engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )

    @staticmethod
    def _bounded_typed_gate_reason(value: object) -> str:
        raw = str(value).strip().casefold()
        normalized = "".join(
            character
            if character.isascii() and (
                character.isalnum() or character in {"_", "-"}
            )
            else "_"
            for character in raw
        ).strip("_")
        return (normalized or "unspecified")[:128]

    def _bind_managed_rev_accepted_input(
        self,
        identity: ChallengeIdentity,
        state: ChallengeState,
        declaration: Mapping[str, object],
        artifact_bindings: Mapping[str, object],
    ) -> tuple[dict[str, object] | None, str | None]:
        """Bind value-free Builder declarations to current Rev evidence."""

        expected_binding_fields = {
            "operator_spec_artifact_path",
            "accepted_input_artifact_path",
        }
        if set(artifact_bindings) != expected_binding_fields:
            return None, "typed_gate_artifact_unbound"
        spec_binding = artifact_bindings.get(
            "operator_spec_artifact_path"
        )
        input_binding = artifact_bindings.get(
            "accepted_input_artifact_path"
        )
        if type(spec_binding) is not dict or type(input_binding) is not dict:
            return None, "typed_gate_artifact_unbound"
        spec_locator = _safe_managed_artifact_locator(
            spec_binding.get("locator")
        )
        input_locator = _safe_managed_artifact_locator(
            input_binding.get("locator")
        )
        spec_digest = declaration.get("operator_spec_sha256")
        input_digest = declaration.get("accepted_input_sha256")
        if (
            spec_locator is None
            or input_locator is None
            or spec_locator == input_locator
            or type(spec_digest) is not str
            or type(input_digest) is not str
            or spec_binding.get("sha256") != spec_digest
            or input_binding.get("sha256") != input_digest
        ):
            return None, "typed_gate_workspace_binding_changed"
        spec_size = spec_binding.get("size_bytes")
        input_size = input_binding.get("size_bytes")
        if (
            type(spec_size) is not int
            or not 1 <= spec_size <= REV_ACCEPTANCE_MAX_SPEC_BYTES
            or type(input_size) is not int
            or not 0 <= input_size <= REV_ACCEPTANCE_MAX_INPUT_BYTES
        ):
            return None, "typed_gate_reference_invalid"
        workspace = (
            self.engine.store.challenge_paths(identity).artifacts
            / "workspace"
        )
        try:
            spec_payload = read_bounded_regular(
                workspace,
                spec_locator,
                maximum_bytes=REV_ACCEPTANCE_MAX_SPEC_BYTES,
                expected_sha256=spec_digest,
                expected_size=spec_size,
            )
            spec = RevAcceptanceOperatorSpec.from_mapping(
                strict_json_loads(
                    spec_payload,
                    max_bytes=REV_ACCEPTANCE_MAX_SPEC_BYTES,
                )
            )
            expected_oracle = (
                validate_rev_acceptance_expected_oracle(
                    declaration.get("expected_oracle")
                )
            )
        except (
            OSError,
            SafeFileError,
            StrictJSONError,
            RevAcceptanceContractError,
            TypeError,
            ValueError,
        ):
            return None, "typed_gate_reference_invalid"
        if (
            spec_payload != rev_canonical_json_bytes(spec.to_dict())
            or spec.evidence_sha256 != spec_digest
            or spec.accepted_input_locator != input_locator
            or spec.expected_oracle != expected_oracle
        ):
            return None, "typed_gate_reference_invalid"
        try:
            binding, _inventory, _challenge_root = (
                self.engine._resolve_rev_stdin_inventory_binding(
                    state,
                    allowed_run_origins=frozenset(
                        {
                            RunOrigin.MANAGED_TOOL,
                            RunOrigin.OPERATOR_TOOL,
                        }
                    ),
                )
            )
            expected_argv = list(
                self.engine._rev_stdin_runner_argv(binding)
            )
        except Exception:
            return None, "typed_gate_reference_invalid"
        declared_argv = declaration.get("declared_argv")
        if (
            type(declared_argv) is not list
            or declared_argv != expected_argv
            or spec.source_locator
            != binding.source_binding.get("path")
        ):
            return None, "typed_gate_reference_invalid"
        return (
            {
                "accepted_input_sha256": input_digest,
                "declared_argv": expected_argv,
                "expected_oracle": expected_oracle,
                "operator_spec_sha256": spec_digest,
            },
            None,
        )

    def _bind_managed_pwn_interaction_recipe(
        self,
        identity: ChallengeIdentity,
        artifact_bindings: Mapping[str, object],
    ) -> tuple[dict[str, object] | None, str | None]:
        """Reparse the exact published data-only interaction recipe."""

        if set(artifact_bindings) != {"recipe_artifact_path"}:
            return None, "typed_gate_artifact_unbound"
        binding = artifact_bindings.get("recipe_artifact_path")
        if type(binding) is not dict:
            return None, "typed_gate_artifact_unbound"
        locator = _safe_managed_artifact_locator(binding.get("locator"))
        digest = binding.get("sha256")
        size = binding.get("size_bytes")
        if (
            locator is None
            or type(digest) is not str
            or type(size) is not int
            or not 1 <= size <= PWN_INTERACTION_V1_MAX_DOCUMENT_BYTES
        ):
            return None, "typed_gate_recipe_invalid"
        workspace = (
            self.engine.store.challenge_paths(identity).artifacts
            / "workspace"
        )
        try:
            payload = read_bounded_regular(
                workspace,
                locator,
                maximum_bytes=PWN_INTERACTION_V1_MAX_DOCUMENT_BYTES,
                expected_sha256=digest,
                expected_size=size,
            )
            recipe = parse_pwn_interaction_v1_recipe(payload)
        except (OSError, SafeFileError, PwnInteractionRecipeError):
            return None, "typed_gate_recipe_invalid"
        if (
            recipe.canonical_bytes != payload
            or recipe.sha256 != digest
        ):
            return None, "typed_gate_recipe_invalid"
        return (
            {
                "recipe_contract_fingerprint": (
                    PWN_INTERACTION_V1_CONTRACT_FINGERPRINT
                ),
                "recipe_sha256": recipe.sha256,
                "recipe_size_bytes": len(recipe.canonical_bytes),
            },
            None,
        )

    def _bind_managed_data_transcript_recipe(
        self,
        identity: ChallengeIdentity,
        state: ChallengeState,
        artifact_bindings: Mapping[str, object],
        *,
        oracle_preissue_id: object,
    ) -> tuple[dict[str, object] | None, str | None]:
        """Bind a closed transcript recipe to one unused private preissue."""

        if set(artifact_bindings) != {"recipe_artifact_path"}:
            return None, "typed_gate_artifact_unbound"
        binding = artifact_bindings.get("recipe_artifact_path")
        if type(binding) is not dict:
            return None, "typed_gate_artifact_unbound"
        locator = _safe_managed_artifact_locator(binding.get("locator"))
        digest = binding.get("sha256")
        size = binding.get("size_bytes")
        if (
            locator is None
            or type(digest) is not str
            or type(size) is not int
            or not 1 <= size <= DATA_TRANSCRIPT_V1_MAX_DOCUMENT_BYTES
            or type(oracle_preissue_id) is not str
        ):
            return None, "typed_gate_recipe_invalid"
        workspace = (
            self.engine.store.challenge_paths(identity).artifacts
            / "workspace"
        )
        try:
            payload = read_bounded_regular(
                workspace,
                locator,
                maximum_bytes=DATA_TRANSCRIPT_V1_MAX_DOCUMENT_BYTES,
                expected_sha256=digest,
                expected_size=size,
            )
            recipe = parse_data_transcript_v1_recipe(payload)
            history = state.extra.get(MANAGED_ORACLE_PREISSUE_STATE_KEY)
            raw_preissue = (
                history.get(oracle_preissue_id)
                if type(history) is dict
                else None
            )
            preissue = validate_managed_oracle_preissue_public_record(
                raw_preissue
            )
        except (
            OSError,
            SafeFileError,
            DataTranscriptContractError,
            ManagedOraclePreissueError,
        ):
            return None, "typed_gate_recipe_invalid"
        category = get_adapter(state.category).name
        expected_kind = (
            MANAGED_ORACLE_PREISSUE_CRYPTO_TRANSCRIPT
            if category == "crypto"
            else MANAGED_ORACLE_PREISSUE_MISC_TRANSCRIPT
            if category == "misc"
            else None
        )
        if (
            expected_kind is None
            or recipe.canonical_bytes != payload
            or recipe.sha256 != digest
            or recipe.category != category
            or recipe.preissue_id != oracle_preissue_id
            or preissue.get("preissue_id") != oracle_preissue_id
            or preissue.get("kind") != expected_kind
            or preissue.get("status") != "unused"
            or preissue.get("issuer") != "operator"
            or preissue.get("configuration_epoch")
            != state.configuration_epoch
            or preissue.get("source_manifest_sha256")
            != state.metadata.get("source_manifest_sha256")
            or preissue.get("image_digest")
            != self.engine.config.runtime.image_digest
            or preissue.get("reset_commitment_sha256")
            != recipe.reset_commitment_sha256
        ):
            return None, "typed_gate_oracle_preissue_invalid"
        return (
            {
                "oracle_preissue_id": oracle_preissue_id,
                "recipe_contract_fingerprint": (
                    DATA_TRANSCRIPT_V1_CONTRACT_FINGERPRINT
                ),
                "recipe_sha256": recipe.sha256,
                "recipe_size_bytes": len(recipe.canonical_bytes),
                "reset_commitment_sha256": (
                    recipe.reset_commitment_sha256
                ),
            },
            None,
        )

    def _execute_typed_gate_experiment(
        self,
        identity: ChallengeIdentity,
        experiment_id: str,
    ) -> ChallengeState:
        """Execute one canonical typed gate and reduce only its real result."""

        current = self.engine.store.load(identity)
        experiment = next(
            (
                item
                for item in current.experiments
                if item.id == experiment_id
            ),
            None,
        )
        if (
            experiment is None
            or experiment.status is not ExperimentStatus.REGISTERED
            or experiment.extra.get("engine_executor")
            != _MANAGED_TYPED_GATE_ENGINE_EXECUTOR
        ):
            raise ManagedError(
                "managed typed gate is not a registered canonical experiment"
            )
        prior_artifact_ids = {item.id for item in current.artifacts}
        prior_run_ids = {item.id for item in current.runs}
        request = experiment.extra.get("managed_typed_gate_request")
        if type(request) is not dict:
            raise ManagedError("managed typed gate request is unavailable")
        kind = request.get("action_kind")
        if (
            type(kind) is not str
            or kind not in MANAGED_TYPED_GATE_ACTION_KINDS
            or request.get("configuration_epoch")
            != current.configuration_epoch
            or experiment.extra.get("configuration_epoch")
            != current.configuration_epoch
        ):
            raise ManagedError("managed typed gate request is stale")
        source_run_id = request.get("source_builder_run_id")
        source_run = next(
            (
                item
                for item in current.runs
                if item.id == source_run_id
            ),
            None,
        )
        if (
            source_run is None
            or source_run.role != Role.BUILDER.value
            or source_run.origin is not RunOrigin.MANAGED_MODEL
            or source_run.status is not RunStatus.COMPLETED
            or source_run.extra.get("semantic_merge") is not True
            or experiment.source_run_id != source_run.id
        ):
            raise ManagedError(
                "managed typed gate lost its Builder run binding"
            )
        bindings = request.get("artifact_bindings")
        if (
            type(bindings) is not dict
            or set(bindings)
            != set(_MANAGED_TYPED_GATE_PATH_FIELDS[kind])
            or not 1 <= len(bindings) <= _MAX_MANAGED_TYPED_GATE_PATHS
        ):
            raise ManagedError(
                "managed typed gate artifact bindings are invalid"
            )
        artifact_index = {item.id: item for item in current.artifacts}
        publish_index = {
            item.id: item for item in current.workspace_publishes
        }
        locators: dict[str, str] = {}
        for field in _MANAGED_TYPED_GATE_PATH_FIELDS[kind]:
            binding = bindings.get(field)
            if type(binding) is not dict or set(binding) != {
                "artifact_id",
                "locator",
                "sha256",
                "size_bytes",
                "workspace_publish_id",
            }:
                raise ManagedError(
                    "managed typed gate artifact binding changed"
                )
            artifact = artifact_index.get(binding.get("artifact_id"))
            publish = publish_index.get(
                binding.get("workspace_publish_id")
            )
            locator = _safe_managed_artifact_locator(
                binding.get("locator")
            )
            if (
                artifact is None
                or publish is None
                or locator is None
                or artifact.id not in experiment.artifact_ids
                or artifact.source_run_id != source_run.id
                or artifact.extra.get("reported_locator") != locator
                or artifact.sha256 != binding.get("sha256")
                or artifact.size != binding.get("size_bytes")
                or publish.run_id != source_run.id
                or publish.destination != locator
                or publish.sha256 != artifact.sha256
                or publish.status != "published"
                or publish.extra.get("size") != artifact.size
                or canonical_workspace_hash(
                    self.engine,
                    identity,
                    locator,
                )
                != artifact.sha256
            ):
                raise ManagedError(
                    "managed typed gate workspace binding changed"
                )
            locators[field] = locator
        if kind == MANAGED_REV_ACCEPTED_INPUT_ACTION_KIND:
            rev_reference, rev_error = (
                self._bind_managed_rev_accepted_input(
                    identity,
                    current,
                    request,
                    bindings,
                )
            )
            if (
                rev_error is not None
                or rev_reference is None
                or any(
                    request.get(field) != value
                    for field, value in rev_reference.items()
                )
            ):
                raise ManagedError(
                    "managed Rev accepted-input declaration changed"
                )
        elif kind == MANAGED_PWN_INTERACTION_ACTION_KIND:
            recipe_reference, recipe_error = (
                self._bind_managed_pwn_interaction_recipe(
                    identity,
                    bindings,
                )
            )
            if (
                recipe_error is not None
                or recipe_reference is None
                or any(
                    request.get(field) != value
                    for field, value in recipe_reference.items()
                )
            ):
                raise ManagedError(
                    "managed Pwn interaction recipe changed"
                )
        elif kind == MANAGED_DATA_TRANSCRIPT_ACTION_KIND:
            transcript_reference, transcript_error = (
                self._bind_managed_data_transcript_recipe(
                    identity,
                    current,
                    bindings,
                    oracle_preissue_id=request.get(
                        "oracle_preissue_id"
                    ),
                )
            )
            if (
                transcript_error is not None
                or transcript_reference is None
                or any(
                    request.get(field) != value
                    for field, value in transcript_reference.items()
                )
            ):
                raise ManagedError(
                    "managed data transcript recipe changed"
                )

        # The managed session already owns the challenge lock. Admission must
        # precede the RUNNING transition so a quota rejection creates no
        # canonical execution intent and no sandbox side effect.
        self.engine._enforce_storage_admission(identity)

        def mark_running(state: ChallengeState) -> None:
            target = next(
                item
                for item in state.experiments
                if item.id == experiment_id
            )
            if (
                target.status is not ExperimentStatus.REGISTERED
                or target.extra.get("managed_typed_gate_request")
                != request
            ):
                raise ManagedError(
                    "managed typed gate changed before execution"
                )
            target.status = ExperimentStatus.RUNNING
            target.extra["started_at"] = utc_now()

        self.engine.store.update(
            identity,
            mark_running,
            expected_revision=current.revision,
        )

        passed = False
        reason_codes: tuple[str, ...] = ()
        evaluation_sha256: str | None = None
        execution_error: Exception | None = None
        try:
            if kind == MANAGED_PWN_EXPLOIT_EFFECT_ACTION_KIND:
                _state, evaluation = self.engine.prove_pwn_exploit_effect(
                    identity,
                    parent_experiment_id=str(
                        request["parent_experiment_id"]
                    ),
                    payload_locator=locators["payload_artifact_path"],
                    timeout_seconds=int(request["timeout_seconds"]),
                    _session_owned=True,
                )
                passed = bool(evaluation.exploit_effect_proven)
                reason_codes = (str(evaluation.reason_code),)
                evaluation_sha256 = str(evaluation.evidence_sha256)
            elif kind == MANAGED_PWN_INTERACTION_ACTION_KIND:
                _state, evaluation = self.engine.prove_pwn_interaction(
                    identity,
                    parent_experiment_id=str(
                        request["parent_experiment_id"]
                    ),
                    recipe_locator=locators["recipe_artifact_path"],
                    timeout_seconds=int(request["timeout_seconds"]),
                    _session_owned=True,
                )
                replay_shape_valid = (
                    evaluation.passed is True
                    and len(evaluation.attack_receipts) == 3
                    and len(evaluation.control_receipts) == 3
                )
                passed = replay_shape_valid
                reason_codes = (
                    (str(evaluation.reason_code),)
                    if replay_shape_valid
                    else ("pwn_interaction_replay_matrix_invalid",)
                )
                evaluation_sha256 = hashlib.sha256(
                    evaluation.canonical_bytes()
                ).hexdigest()
            elif kind == MANAGED_REV_ACCEPTED_INPUT_ACTION_KIND:
                _state, evaluation = (
                    self.engine.prove_rev_accepted_input(
                        identity,
                        operator_spec_locator=locators[
                            "operator_spec_artifact_path"
                        ],
                        timeout_seconds=int(request["timeout_seconds"]),
                        _session_owned=True,
                    )
                )
                normalized_evaluation = (
                    validate_rev_acceptance_evaluation(evaluation)
                )
                passed = normalized_evaluation["passed"] is True
                reason_codes = tuple(
                    str(item)
                    for item in normalized_evaluation["reason_codes"]
                )
                evaluation_sha256 = rev_sha256(
                    rev_canonical_json_bytes(normalized_evaluation)
                )
            elif kind == MANAGED_WEB_IMPACT_ACTION_KIND:
                _state, evaluation = self.engine.prove_web_impact(
                    identity,
                    operator_spec_locator=locators[
                        "operator_spec_artifact_path"
                    ],
                    driver_locator=locators["driver_artifact_path"],
                    hypothesis_ids=tuple(request["hypothesis_ids"]),
                    timeout_seconds=int(request["timeout_seconds"]),
                    _session_owned=True,
                )
                passed = bool(evaluation.confirmed)
                reason_codes = tuple(evaluation.reason_codes)
                evaluation_sha256 = str(evaluation.sha256)
            elif kind == MANAGED_WEB_ACTIVE_PROBE_ACTION_KIND:
                _state, evaluation = (
                    self.engine.prove_web_active_probe(
                        identity,
                        operator_spec_locator=locators[
                            "operator_spec_artifact_path"
                        ],
                        driver_locator=locators[
                            "driver_artifact_path"
                        ],
                        hypothesis_ids=tuple(
                            request["hypothesis_ids"]
                        ),
                        timeout_seconds=int(
                            request["timeout_seconds"]
                        ),
                        _session_owned=True,
                    )
                )
                passed = evaluation["confirmed"] is True
                reason_codes = tuple(
                    str(item)
                    for item in evaluation["reason_codes"]
                )
                evaluation_sha256 = str(
                    evaluation["evaluation_sha256"]
                )
            elif kind == MANAGED_CRYPTO_METAMORPHIC_ACTION_KIND:
                _state, evaluation = (
                    self.engine.prove_crypto_metamorphic_candidate(
                        identity,
                        str(request["candidate_id"]),
                        solver_locator=locators[
                            "solver_artifact_path"
                        ],
                        original_parameters_locator=locators[
                            "original_parameters_artifact_path"
                        ],
                        runtime=str(request["runtime"]),
                        oracle_preissue_id=str(
                            request["oracle_preissue_id"]
                        ),
                        _session_owned=True,
                        _managed_builder_run_id=source_run.id,
                        _managed_experiment_id=experiment_id,
                    )
                )
                passed = bool(evaluation.passed)
                reason_codes = tuple(evaluation.failures)
                evaluation_sha256 = None
            elif kind == MANAGED_FORENSIC_ASSERTION_ACTION_KIND:
                _state, evaluation = self.engine.prove_forensic_assertion(
                    identity,
                    operator_spec_locator=locators[
                        "operator_spec_artifact_path"
                    ],
                    hypothesis_ids=tuple(request["hypothesis_ids"]),
                    timeout_seconds=int(request["timeout_seconds"]),
                    _session_owned=True,
                )
                passed = bool(evaluation.confirmed)
                reason_codes = tuple(evaluation.reason_codes)
                evaluation_sha256 = str(evaluation.sha256)
            elif kind == MANAGED_MISC_TRANSFORM_ACTION_KIND:
                _state, evaluation = (
                    self.engine.evaluate_misc_transform_candidate(
                        identity,
                        str(request["candidate_id"]),
                        spec_locator=locators["spec_artifact_path"],
                        oracle_preissue_id=str(
                            request["oracle_preissue_id"]
                        ),
                        _session_owned=True,
                        _managed_builder_run_id=source_run.id,
                        _managed_experiment_id=experiment_id,
                    )
                )
                passed = bool(evaluation.passed)
                reason_codes = tuple(evaluation.failure_codes)
                evaluation_sha256 = str(evaluation.sha256)
            elif kind == MANAGED_DATA_TRANSCRIPT_ACTION_KIND:
                recipe_binding = bindings["recipe_artifact_path"]
                _state, evaluation = self.engine.prove_data_transcript(
                    identity,
                    recipe_locator=locators[
                        "recipe_artifact_path"
                    ],
                    recipe_artifact_id=str(
                        recipe_binding["artifact_id"]
                    ),
                    recipe_sha256=str(recipe_binding["sha256"]),
                    recipe_size_bytes=int(
                        recipe_binding["size_bytes"]
                    ),
                    oracle_preissue_id=str(
                        request["oracle_preissue_id"]
                    ),
                    _session_owned=True,
                    _managed_builder_run_id=source_run.id,
                    _managed_experiment_id=experiment_id,
                )
                passed = bool(evaluation.passed)
                reason_codes = (str(evaluation.reason_code),)
                evaluation_sha256 = hashlib.sha256(
                    evaluation.canonical_bytes()
                ).hexdigest()
            else:  # pragma: no cover - guarded by the exact kind check.
                raise ManagedError("unsupported managed typed gate")
        except Exception as error:
            execution_error = error
            reason_codes = ("typed_gate_execution_error",)

        bounded_reasons = tuple(
            dict.fromkeys(
                self._bounded_typed_gate_reason(item)
                for item in reason_codes[:16]
            )
        )
        if not bounded_reasons and not passed:
            bounded_reasons = ("typed_gate_nonpass",)
        terminal = self.engine.store.load(identity)
        evidence_artifact_ids = tuple(
            item.id
            for item in terminal.artifacts
            if item.id not in prior_artifact_ids
        )
        evidence_run_ids = tuple(
            item.id
            for item in terminal.runs
            if item.id not in prior_run_ids
        )

        if kind == MANAGED_DATA_TRANSCRIPT_ACTION_KIND:
            target = next(
                (
                    item
                    for item in terminal.experiments
                    if item.id == experiment_id
                ),
                None,
            )
            result = target.result if target is not None else None
            result_artifact_ids = (
                result.get("evidence_artifact_ids")
                if type(result) is dict
                else None
            )
            result_run_ids = (
                result.get("evidence_run_ids")
                if type(result) is dict
                else None
            )
            if (
                target is not None
                and target.status
                in {
                    ExperimentStatus.COMPLETED,
                    ExperimentStatus.FAILED,
                }
                and type(result) is dict
                and set(result)
                == {
                    "action_kind",
                    "authority",
                    "evaluation_sha256",
                    "evidence_artifact_ids",
                    "evidence_run_ids",
                    "execution_error_type",
                    "passed",
                    "reason_codes",
                    "schema_version",
                }
            ):
                artifact_ids = {item.id for item in terminal.artifacts}
                run_ids = {item.id for item in terminal.runs}
                terminal_passed = result.get("passed")
                reason_values = result.get("reason_codes")
                terminal_status_exact = (
                    terminal_passed is True
                    and target.status is ExperimentStatus.COMPLETED
                ) or (
                    terminal_passed is False
                    and target.status is ExperimentStatus.FAILED
                )
                if (
                    result["schema_version"] == 1
                    and result["action_kind"] == kind
                    and result["authority"]
                    == "engine_deterministic_gate"
                    and terminal_status_exact
                    and type(reason_values) is list
                    and bool(reason_values)
                    and all(
                        type(item) is str
                        and bool(item)
                        and len(item) <= 160
                        for item in reason_values
                    )
                    and (
                        (
                            terminal_passed is True
                            and type(
                                result["evaluation_sha256"]
                            )
                            is str
                            and len(result["evaluation_sha256"]) == 64
                            and result["execution_error_type"] is None
                        )
                        or (
                            terminal_passed is False
                            and result["evaluation_sha256"] is None
                            and type(
                                result["execution_error_type"]
                            )
                            is str
                            and bool(result["execution_error_type"])
                        )
                    )
                    and type(result_artifact_ids) is list
                    and len(result_artifact_ids)
                    == len(set(result_artifact_ids))
                    and all(
                        type(item) is str and item in artifact_ids
                        for item in result_artifact_ids
                    )
                    and set(result_artifact_ids).issubset(
                        target.artifact_ids
                    )
                    and result_artifact_ids
                    == list(evidence_artifact_ids)
                    and type(result_run_ids) is list
                    and len(result_run_ids)
                    == len(set(result_run_ids))
                    and all(
                        type(item) is str and item in run_ids
                        for item in result_run_ids
                    )
                    and result_run_ids == list(evidence_run_ids)
                ):
                    return terminal
                raise ManagedError(
                    "managed data transcript terminal result is invalid"
                )
            if (
                target is not None
                and target.status is not ExperimentStatus.RUNNING
            ):
                raise ManagedError(
                    "managed data transcript changed during execution"
                )

        def mark_terminal(state: ChallengeState) -> None:
            target = next(
                item
                for item in state.experiments
                if item.id == experiment_id
            )
            if (
                target.status is not ExperimentStatus.RUNNING
                or target.extra.get("managed_typed_gate_request")
                != request
            ):
                raise ManagedError(
                    "managed typed gate changed during execution"
                )
            target.status = (
                ExperimentStatus.COMPLETED
                if passed
                else ExperimentStatus.FAILED
            )
            target.artifact_ids = list(
                dict.fromkeys(
                    (*target.artifact_ids, *evidence_artifact_ids)
                )
            )
            target.result = {
                "schema_version": 1,
                "action_kind": kind,
                "authority": "engine_deterministic_gate",
                "passed": passed,
                "reason_codes": list(bounded_reasons),
                "evaluation_sha256": evaluation_sha256,
                "evidence_artifact_ids": list(evidence_artifact_ids),
                "evidence_run_ids": list(evidence_run_ids),
                "execution_error_type": (
                    type(execution_error).__name__[:128]
                    if execution_error is not None
                    else None
                ),
            }
            target.extra["completed_at"] = utc_now()

        return self.engine.store.update(
            identity,
            mark_terminal,
            expected_revision=terminal.revision,
        )

    def _terminalize_typed_gate_dispatch_rejection(
        self,
        identity: ChallengeIdentity,
        experiment_id: str,
        error: Exception,
    ) -> ChallengeState:
        """Make a pre-dispatch rejection capsule-safe without raw text."""

        current = self.engine.store.load(identity)

        def apply(state: ChallengeState) -> None:
            target = next(
                (
                    item
                    for item in state.experiments
                    if item.id == experiment_id
                ),
                None,
            )
            if (
                target is None
                or target.extra.get("engine_executor")
                != _MANAGED_TYPED_GATE_ENGINE_EXECUTOR
                or target.status
                not in {
                    ExperimentStatus.REGISTERED,
                    ExperimentStatus.RUNNING,
                }
            ):
                raise ManagedError(
                    "typed gate dispatch rejection lost its experiment"
                )
            target.status = ExperimentStatus.FAILED
            target.result = {
                "schema_version": 1,
                "action_kind": target.extra.get("managed_action_kind"),
                "authority": "engine_deterministic_gate",
                "passed": False,
                "reason_codes": ["typed_gate_dispatch_rejected"],
                "evaluation_sha256": None,
                "evidence_artifact_ids": [],
                "evidence_run_ids": [],
                "execution_error_type": type(error).__name__[:128],
            }
            target.extra["completed_at"] = utc_now()

        return self.engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )

    def _apply_builder_publishes(
        self,
        identity: ChallengeIdentity,
        wave: ManagedWave,
        results: Sequence[Any],
    ) -> BuilderPublishOutcome:
        """Promote explicit writes and one shape-valid typed-gate input set."""

        proposals: list[tuple[str, str, int, int]] = []
        proposed_paths: set[tuple[str, str]] = set()
        state = self.engine.store.load(identity)
        adapter_name = get_adapter(state.category).name
        typed_action_count = sum(
            1
            for result in results
            for action in (
                result.output.get("actions", [])
                if isinstance(result.output, Mapping)
                and isinstance(result.output.get("actions"), list)
                else ()
            )
            if isinstance(action, Mapping)
            and action.get("kind") in MANAGED_TYPED_GATE_ACTION_KINDS
        )
        for result in results:
            if result.invocation.role is not Role.BUILDER:
                continue
            output = result.output
            actions = (
                output.get("actions")
                if isinstance(output, Mapping)
                else None
            )
            if not isinstance(actions, list):
                continue
            proposal_ordinal = 0
            for action in actions:
                if not isinstance(action, Mapping):
                    continue
                kind = action.get("kind")
                relative_paths: tuple[object, ...] = ()
                if kind == "write_artifact":
                    relative_paths = (action.get("artifact_path"),)
                elif (
                    typed_action_count == 1
                    and kind in MANAGED_TYPED_GATE_ACTION_KINDS
                    and _managed_typed_gate_action_shape_error(action)
                    is None
                    and _managed_typed_gate_category_matches(
                        str(kind),
                        adapter_name,
                    )
                    and wave.kind is WaveKind.ATTACK
                ):
                    relative_paths = tuple(
                        action.get(field)
                        for field in _MANAGED_TYPED_GATE_PATH_FIELDS[
                            str(kind)
                        ]
                    )
                for relative in relative_paths:
                    if not isinstance(relative, str):
                        continue
                    proposal_ordinal += 1
                    key = (result.invocation.run_id, relative)
                    if key in proposed_paths:
                        continue
                    proposed_paths.add(key)
                    proposals.append(
                        (
                            result.invocation.run_id,
                            relative,
                            proposal_ordinal,
                            max(
                                1,
                                min(
                                    MANAGED_REJECTION_V1_MAX_ATTEMPT,
                                    len(result.attempts),
                                ),
                            ),
                        )
                    )
        if len(proposals) > 8:
            raise ManagedError("Builder proposed too many workspace publishes")
        published_count = 0
        for run_id, relative, proposal_ordinal, attempt in proposals:
            state = self.engine.store.load(identity)
            try:
                publish_builder_file(
                    self.engine,
                    identity,
                    run_id=run_id,
                    staged_path=relative,
                    destination=relative,
                    base_workspace_revision=state.workspace_revision,
                    base_sha256=canonical_workspace_hash(
                        self.engine,
                        identity,
                        relative,
                    ),
                    _session_owned=True,
                )
            except WorkspacePublishProposalRejected as error:
                rejection = BuilderPublishRejection(
                    run_id=run_id,
                    proposal_ordinal=proposal_ordinal,
                    code=error.code,
                )
                current = self.engine.store.load(identity)

                def record_rejection(latest: ChallengeState) -> None:
                    self._require_epoch(latest, wave.session_id)
                    canonical_wave = next(
                        (
                            item
                            for item in latest.waves
                            if item.id == wave.id
                        ),
                        None,
                    )
                    if (
                        canonical_wave is None
                        or canonical_wave.cycle_id != wave.cycle_id
                        or canonical_wave.role_run_ids
                        != wave.role_run_ids
                        or run_id
                        != canonical_wave.role_run_ids.get(
                            Role.BUILDER.value
                        )
                    ):
                        raise ManagedError(
                            "Builder publication rejection lost its "
                            "canonical wave binding"
                        )
                    builder_run = next(
                        (
                            run
                            for run in latest.runs
                            if run.id == run_id
                        ),
                        None,
                    )
                    if (
                        builder_run is None
                        or builder_run.role != Role.BUILDER.value
                        or builder_run.status is not RunStatus.COMPLETED
                        or builder_run.origin
                        is not RunOrigin.MANAGED_MODEL
                    ):
                        raise ManagedError(
                            "Builder publication rejection lost its "
                            "canonical run binding"
                        )
                    try:
                        builder_run.extra["managed_rejection_v1"] = (
                            _merge_builder_publish_rejection(
                                builder_run.extra.get(
                                    "managed_rejection_v1"
                                ),
                                attempt=attempt,
                                proposal_ordinal=proposal_ordinal,
                                code=error.code,
                            )
                        )
                    except ManagedRejectionV1ContractError as contract_error:
                        raise ManagedError(
                            "Builder publication rejection could not be "
                            "represented safely"
                        ) from contract_error
                    cycle = next(
                        (
                            item
                            for item in latest.cycles
                            if item.id == canonical_wave.cycle_id
                        ),
                        None,
                    )
                    if cycle is None:
                        raise ManagedError(
                            "Builder publication rejection lost its cycle"
                        )
                    cycle.selected_action_ids = []
                    wave_run_ids = set(
                        canonical_wave.role_run_ids.values()
                    )
                    for experiment in latest.experiments:
                        if (
                            experiment.source_run_id in wave_run_ids
                            and experiment.status
                            is ExperimentStatus.REGISTERED
                        ):
                            experiment.status = ExperimentStatus.CANCELLED
                            experiment.extra["cancelled_at"] = utc_now()
                            experiment.extra["cancelled_reason"] = (
                                "builder_publish_rejected"
                            )

                self.engine.store.update(
                    identity,
                    record_rejection,
                    expected_revision=current.revision,
                )
                return BuilderPublishOutcome(
                    published_count=published_count,
                    rejection=rejection,
                )
            published_count += 1
        return BuilderPublishOutcome(published_count=published_count)

    def _register_pwn_crash_actions(
        self,
        identity: ChallengeIdentity,
        wave: ManagedWave,
        results: Sequence[Any],
    ) -> ChallengeState:
        """Turn one v2 Builder request into an engine-owned crash proposal."""

        proposals: list[tuple[Any, int, Mapping[str, Any]]] = []
        for result in results:
            output = result.output
            actions = (
                output.get("actions")
                if isinstance(output, Mapping)
                else None
            )
            if not isinstance(actions, list):
                continue
            for index, action in enumerate(actions, start=1):
                if (
                    isinstance(action, Mapping)
                    and action.get("kind")
                    == MANAGED_PWN_CRASH_ACTION_KIND
                ):
                    proposals.append((result, index, action))
        if not proposals:
            return self.engine.store.load(identity)

        current = self.engine.store.load(identity)

        def apply(state: ChallengeState) -> None:
            self._require_epoch(state, wave.session_id)
            canonical_wave = next(
                (item for item in state.waves if item.id == wave.id),
                None,
            )
            if canonical_wave is None:
                raise ManagedError(
                    f"unknown managed wave for Pwn crash action: {wave.id}"
                )

            for result, index, action in proposals:
                invocation = result.invocation
                run = next(
                    (
                        item
                        for item in state.runs
                        if item.id == invocation.run_id
                    ),
                    None,
                )
                if run is None:
                    raise ManagedError(
                        "Pwn crash action references an unknown managed run: "
                        f"{invocation.run_id}"
                    )

                def reject(reason: str) -> None:
                    bucket = run.extra.setdefault("rejected_actions", [])
                    if isinstance(bucket, list):
                        entry = {
                            "action": str(index),
                            "reason": reason[:1024],
                        }
                        if len(bucket) > _MAX_MANAGED_REJECTED_ACTIONS:
                            del bucket[_MAX_MANAGED_REJECTED_ACTIONS:]
                        if (
                            entry not in bucket
                            and len(bucket) < _MAX_MANAGED_REJECTED_ACTIONS
                        ):
                            bucket.append(entry)

                if state.category.strip().casefold() != "pwn":
                    reject("verify_pwn_crash is restricted to category pwn")
                    continue
                if canonical_wave.kind is not WaveKind.ATTACK:
                    reject(
                        "verify_pwn_crash is restricted to an ATTACK wave"
                    )
                    continue
                if (
                    invocation.role is not Role.BUILDER
                    or canonical_wave.role_run_ids.get("builder")
                    != invocation.run_id
                    or run.role != Role.BUILDER.value
                ):
                    reject(
                        "verify_pwn_crash is restricted to the reserved "
                        "ATTACK Builder"
                    )
                    continue
                if invocation.contract_version != 2:
                    reject("verify_pwn_crash requires the v2 role contract")
                    continue
                if (
                    run.origin is not RunOrigin.MANAGED_MODEL
                    or run.wave_id != canonical_wave.id
                    or run.session_id != canonical_wave.session_id
                    or run.cycle_id != canonical_wave.cycle_id
                    or run.configuration_epoch != state.configuration_epoch
                    or run.status is not RunStatus.COMPLETED
                    or run.extra.get("semantic_merge") is not True
                ):
                    reject(
                        "verify_pwn_crash requires the current semantically "
                        "merged Builder result"
                    )
                    continue

                payload_locator = _safe_managed_artifact_locator(
                    action.get("payload_artifact_path")
                )
                if payload_locator is None:
                    reject(
                        "verify_pwn_crash payload locator is not a safe "
                        "relative path"
                    )
                    continue
                payload_matches = [
                    artifact
                    for artifact in state.artifacts
                    if artifact.source_run_id == invocation.run_id
                    and artifact.extra.get("reported_locator")
                    == payload_locator
                ]
                if len(payload_matches) != 1:
                    reject(
                        "verify_pwn_crash payload locator must resolve to "
                        "exactly one normalized artifact from the current "
                        f"Builder result; observed {len(payload_matches)}"
                    )
                    continue
                payload = payload_matches[0]
                if (
                    type(payload.size) is not int
                    or payload.size <= 0
                    or payload.size > PWN_CRASH_V1_MAX_INPUT_BYTES
                ):
                    reject(
                        "verify_pwn_crash payload artifact must be non-empty "
                        f"and at most {PWN_CRASH_V1_MAX_INPUT_BYTES} bytes"
                    )
                    continue

                requested_hypothesis = action.get("hypothesis_id")
                if not isinstance(requested_hypothesis, str):
                    reject(
                        "verify_pwn_crash hypothesis_id must be a string"
                    )
                    continue
                local_hypothesis_ids = {
                    str(item.get("id"))
                    for item in (
                        result.output.get("hypotheses", [])
                        if isinstance(result.output, Mapping)
                        else []
                    )
                    if isinstance(item, Mapping)
                    and isinstance(item.get("id"), str)
                }
                hypothesis_matches = {
                    hypothesis.id
                    for hypothesis in state.hypotheses
                    if (
                        hypothesis.status in ACTIVE_HYPOTHESIS_STATUSES
                        and (
                            hypothesis.id == requested_hypothesis
                            or (
                                requested_hypothesis
                                in local_hypothesis_ids
                                and hypothesis.id
                                == (
                                    f"H-{invocation.run_id}-"
                                    f"{requested_hypothesis}"
                                )
                                and hypothesis.source_run_id
                                == invocation.run_id
                            )
                        )
                    )
                }
                if len(hypothesis_matches) != 1:
                    reject(
                        "verify_pwn_crash hypothesis_id must resolve to "
                        "exactly one active local or canonical hypothesis"
                    )
                    continue
                hypothesis_id = next(iter(hypothesis_matches))

                experiment_id = _stable_id(
                    "E",
                    identity.key,
                    canonical_wave.id,
                    invocation.run_id,
                    index,
                )
                existing = next(
                    (
                        item
                        for item in state.experiments
                        if item.id == experiment_id
                    ),
                    None,
                )
                request = {
                    "schema_version": 1,
                    "contract_id": PWN_CRASH_V1_CONTRACT_ID,
                    "contract_version": PWN_CRASH_V1_CONTRACT_VERSION,
                    "contract_fingerprint": (
                        PWN_CRASH_V1_CONTRACT_FINGERPRINT
                    ),
                    "protocol": PWN_CRASH_V1_PROTOCOL,
                    "configuration_epoch": state.configuration_epoch,
                    "payload_artifact_id": payload.id,
                    "payload_reported_locator": payload_locator,
                    "payload_sha256": payload.sha256,
                    "payload_size_bytes": payload.size,
                    "hypothesis_id": hypothesis_id,
                    "source_builder_run_id": invocation.run_id,
                }
                if existing is not None:
                    if (
                        existing.command != _PWN_CRASH_ENGINE_COMMAND
                        or existing.hypothesis_ids != [hypothesis_id]
                        or existing.artifact_ids != [payload.id]
                        or existing.extra.get("pwn_crash_request")
                        != request
                    ):
                        raise ManagedError(
                            "Pwn crash action idempotency collision: "
                            f"{experiment_id}"
                        )
                    continue
                state.experiments.append(
                    Experiment(
                        id=experiment_id,
                        hypothesis_ids=[hypothesis_id],
                        command=_PWN_CRASH_ENGINE_COMMAND,
                        expected_observation=(
                            "the same allowlisted target fault signal occurs "
                            "in at least two of three exact-input runs while "
                            "all three empty-input controls exit normally"
                        ),
                        keep_if=(
                            "the engine-owned v1 differential evaluator "
                            "returns CONFIRMED"
                        ),
                        drop_if=(
                            "the v1 contract fails closed or the differential "
                            "positive/control condition is not satisfied"
                        ),
                        timeout_seconds=self.engine._budget_command_timeout(
                            state,
                            60,
                        ),
                        resource_class="standard",
                        kind=ExperimentKind.STRATEGIC,
                        status=ExperimentStatus.REGISTERED,
                        source_run_id=invocation.run_id,
                        artifact_ids=[payload.id],
                        extra={
                            "managed_contract_version": 2,
                            "managed_action_kind": (
                                MANAGED_PWN_CRASH_ACTION_KIND
                            ),
                            "engine_executor": (
                                _PWN_CRASH_ENGINE_EXECUTOR
                            ),
                            "configuration_epoch": (
                                state.configuration_epoch
                            ),
                            "pwn_crash_request": request,
                        },
                    )
                )

        return self.engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )

    def _register_typed_gate_actions(
        self,
        identity: ChallengeIdentity,
        wave: ManagedWave,
        results: Sequence[Any],
    ) -> ManagedTypedGateRegistrationOutcome:
        """Bind one Builder-authored category gate to canonical inputs.

        The model supplies only relative paths and canonical record ids.  This
        reducer accepts a path only when the current Builder both reported the
        bounded artifact and atomically published the exact same bytes.  The
        durable request contains no model verdict; execution is deferred to
        the engine-owned dispatcher.
        """

        proposals: list[tuple[Any, int, Mapping[str, Any]]] = []
        for result in results:
            output = result.output
            actions = (
                output.get("actions")
                if isinstance(output, Mapping)
                else None
            )
            if not isinstance(actions, list):
                continue
            for index, action in enumerate(actions, start=1):
                if (
                    isinstance(action, Mapping)
                    and action.get("kind")
                    in MANAGED_TYPED_GATE_ACTION_KINDS
                ):
                    proposals.append((result, index, action))
        if not proposals:
            return ManagedTypedGateRegistrationOutcome()

        current = self.engine.store.load(identity)
        rejection_codes: list[str] = []
        registered_ids: list[str] = []

        def apply(state: ChallengeState) -> None:
            self._require_epoch(state, wave.session_id)
            canonical_wave = next(
                (item for item in state.waves if item.id == wave.id),
                None,
            )
            if canonical_wave is None:
                raise ManagedError(
                    f"unknown managed wave for typed gate: {wave.id}"
                )

            def reject(
                run: RunReference | None,
                index: int,
                code: str,
            ) -> None:
                rejection_codes.append(code)
                if run is None:
                    return
                bucket = run.extra.setdefault("rejected_actions", [])
                if not isinstance(bucket, list):
                    return
                entry = {
                    "action": str(index),
                    "reason": code,
                }
                if (
                    entry not in bucket
                    and len(bucket) < _MAX_MANAGED_REJECTED_ACTIONS
                ):
                    bucket.append(entry)

            if len(proposals) != 1:
                for result, index, _action in proposals[
                    :_MAX_MANAGED_REJECTED_ACTIONS
                ]:
                    reject(
                        next(
                            (
                                item
                                for item in state.runs
                                if item.id == result.invocation.run_id
                            ),
                            None,
                        ),
                        index,
                        "typed_gate_multiple_actions",
                    )
                return

            result, index, action = proposals[0]
            invocation = result.invocation
            run = next(
                (
                    item
                    for item in state.runs
                    if item.id == invocation.run_id
                ),
                None,
            )
            if run is None:
                reject(None, index, "typed_gate_unknown_run")
                return
            kind = action.get("kind")
            if not isinstance(kind, str):
                reject(run, index, "typed_gate_action_invalid")
                return
            if (
                not _managed_typed_gate_category_matches(
                    kind,
                    get_adapter(state.category).name,
                )
            ):
                reject(run, index, "typed_gate_wrong_category")
                return
            if canonical_wave.kind is not WaveKind.ATTACK:
                reject(run, index, "typed_gate_wrong_wave")
                return
            if (
                invocation.role is not Role.BUILDER
                or canonical_wave.role_run_ids.get(Role.BUILDER.value)
                != invocation.run_id
                or run.role != Role.BUILDER.value
            ):
                reject(run, index, "typed_gate_wrong_role")
                return
            if invocation.contract_version != 2:
                reject(run, index, "typed_gate_wrong_contract")
                return
            if (
                run.origin is not RunOrigin.MANAGED_MODEL
                or run.wave_id != canonical_wave.id
                or run.session_id != canonical_wave.session_id
                or run.cycle_id != canonical_wave.cycle_id
                or run.configuration_epoch != state.configuration_epoch
                or run.status is not RunStatus.COMPLETED
                or run.extra.get("semantic_merge") is not True
            ):
                reject(run, index, "typed_gate_stale_run")
                return

            shape_error = _managed_typed_gate_action_shape_error(action)
            if shape_error is not None:
                reject(run, index, shape_error)
                return

            # Both canonical Pwn gates deliberately run in a deny-all local
            # sandbox.  A selected target makes either request semantically
            # unexecutable, even though its provider schema is valid.  Reject
            # before creating a durable execution intent; Builder publication
            # has already completed, so the authored exploit/recipe remains
            # available for a target-bound command in a later cycle.
            if (
                kind in _MANAGED_LOCAL_PWN_TYPED_GATE_KINDS
                and state.primary_target_id is not None
            ):
                reject(
                    run,
                    index,
                    _MANAGED_PWN_REMOTE_TARGET_REJECTION,
                )
                return

            artifact_bindings: dict[str, dict[str, object]] = {}
            locators: set[str] = set()
            for field in _MANAGED_TYPED_GATE_PATH_FIELDS[kind]:
                locator = _safe_managed_artifact_locator(action.get(field))
                if locator is None or locator in locators:
                    reject(run, index, "typed_gate_path_invalid")
                    return
                locators.add(locator)
                matches = [
                    artifact
                    for artifact in state.artifacts
                    if artifact.source_run_id == invocation.run_id
                    and artifact.extra.get("reported_locator") == locator
                ]
                publishes = [
                    publish
                    for publish in state.workspace_publishes
                    if publish.run_id == invocation.run_id
                    and publish.destination == locator
                    and publish.status == "published"
                ]
                if len(matches) != 1 or len(publishes) != 1:
                    reject(run, index, "typed_gate_artifact_unbound")
                    return
                artifact = matches[0]
                publish = publishes[0]
                minimum_size = (
                    0
                    if (
                        kind == MANAGED_REV_ACCEPTED_INPUT_ACTION_KIND
                        and field == "accepted_input_artifact_path"
                    )
                    else 1
                )
                if (
                    type(artifact.size) is not int
                    or artifact.size < minimum_size
                    or artifact.size > self.engine.store.max_artifact_bytes
                    or artifact.sha256 != publish.sha256
                    or publish.extra.get("size") != artifact.size
                    or canonical_workspace_hash(
                        self.engine,
                        identity,
                        locator,
                    )
                    != artifact.sha256
                ):
                    reject(
                        run,
                        index,
                        "typed_gate_workspace_binding_changed",
                    )
                    return
                artifact_bindings[field] = {
                    "artifact_id": artifact.id,
                    "locator": locator,
                    "sha256": artifact.sha256,
                    "size_bytes": artifact.size,
                    "workspace_publish_id": publish.id,
                }

            local_hypothesis_ids = {
                str(item.get("id"))
                for item in (
                    result.output.get("hypotheses", [])
                    if isinstance(result.output, Mapping)
                    else []
                )
                if isinstance(item, Mapping)
                and isinstance(item.get("id"), str)
            }
            requested_hypotheses = action.get("hypothesis_ids", [])
            if (
                type(requested_hypotheses) is not list
                or len(requested_hypotheses) > 64
                or any(type(item) is not str for item in requested_hypotheses)
                or len(set(requested_hypotheses))
                != len(requested_hypotheses)
            ):
                reject(run, index, "typed_gate_hypothesis_invalid")
                return
            resolved_hypotheses: list[str] = []
            active_hypotheses = {
                item.id: item
                for item in state.hypotheses
                if item.status in ACTIVE_HYPOTHESIS_STATUSES
            }
            for requested in requested_hypotheses:
                candidates = {
                    hypothesis_id
                    for hypothesis_id, hypothesis in active_hypotheses.items()
                    if (
                        hypothesis_id == requested
                        or (
                            requested in local_hypothesis_ids
                            and hypothesis_id
                            == f"H-{invocation.run_id}-{requested}"
                            and hypothesis.source_run_id == invocation.run_id
                        )
                    )
                }
                if len(candidates) != 1:
                    reject(run, index, "typed_gate_hypothesis_invalid")
                    return
                resolved_hypotheses.append(next(iter(candidates)))

            reference: dict[str, object] = {}
            if kind in {
                MANAGED_PWN_EXPLOIT_EFFECT_ACTION_KIND,
                MANAGED_PWN_INTERACTION_ACTION_KIND,
            }:
                parent_id = action.get("parent_experiment_id")
                if (
                    type(parent_id) is not str
                    or not any(
                        item.id == parent_id for item in state.experiments
                    )
                ):
                    reject(run, index, "typed_gate_reference_invalid")
                    return
                timeout = action.get("timeout_seconds")
                if (
                    type(timeout) is not int
                    or not 1 <= timeout <= 3600
                ):
                    reject(run, index, "typed_gate_timeout_invalid")
                    return
                reference = {
                    "parent_experiment_id": parent_id,
                    "timeout_seconds": self.engine._budget_command_timeout(
                        state,
                        timeout,
                    ),
                }
                if kind == MANAGED_PWN_INTERACTION_ACTION_KIND:
                    recipe_reference, recipe_error = (
                        self._bind_managed_pwn_interaction_recipe(
                            identity,
                            artifact_bindings,
                        )
                    )
                    if (
                        recipe_error is not None
                        or recipe_reference is None
                    ):
                        reject(
                            run,
                            index,
                            recipe_error
                            or "typed_gate_recipe_invalid",
                        )
                        return
                    reference.update(recipe_reference)
            elif kind == MANAGED_REV_ACCEPTED_INPUT_ACTION_KIND:
                rev_reference, rev_error = (
                    self._bind_managed_rev_accepted_input(
                        identity,
                        state,
                        action,
                        artifact_bindings,
                    )
                )
                if rev_error is not None or rev_reference is None:
                    reject(
                        run,
                        index,
                        rev_error or "typed_gate_reference_invalid",
                    )
                    return
                reference = {
                    **rev_reference,
                    "timeout_seconds": (
                        self.engine._budget_command_timeout(
                            state,
                            min(
                                300,
                                self.engine.config.runtime.command_timeout_s,
                            ),
                        )
                    ),
                }
            elif kind in {
                MANAGED_WEB_IMPACT_ACTION_KIND,
                MANAGED_WEB_ACTIVE_PROBE_ACTION_KIND,
                MANAGED_FORENSIC_ASSERTION_ACTION_KIND,
            }:
                timeout = action.get("timeout_seconds")
                if (
                    type(timeout) is not int
                    or not 1 <= timeout <= 86_400
                ):
                    reject(run, index, "typed_gate_timeout_invalid")
                    return
                reference = {
                    "hypothesis_ids": list(resolved_hypotheses),
                    "timeout_seconds": self.engine._budget_command_timeout(
                        state,
                        timeout,
                    ),
                }
            elif kind == MANAGED_DATA_TRANSCRIPT_ACTION_KIND:
                transcript_reference, transcript_error = (
                    self._bind_managed_data_transcript_recipe(
                        identity,
                        state,
                        artifact_bindings,
                        oracle_preissue_id=action.get(
                            "oracle_preissue_id"
                        ),
                    )
                )
                oracle_preissue_id = action.get("oracle_preissue_id")
                history = state.extra.get(
                    MANAGED_ORACLE_PREISSUE_STATE_KEY
                )
                raw_preissue = (
                    history.get(oracle_preissue_id)
                    if type(history) is dict
                    and type(oracle_preissue_id) is str
                    else None
                )
                try:
                    preissue = (
                        validate_managed_oracle_preissue_public_record(
                            raw_preissue
                        )
                    )
                except ManagedOraclePreissueError:
                    preissue = {}
                if (
                    transcript_error is not None
                    or transcript_reference is None
                    or run.base_revision
                    <= int(preissue.get("issue_revision", 0))
                ):
                    reject(
                        run,
                        index,
                        transcript_error
                        or "typed_gate_oracle_preissue_invalid",
                    )
                    return
                reference = transcript_reference
            elif kind in {
                MANAGED_CRYPTO_METAMORPHIC_ACTION_KIND,
                MANAGED_MISC_TRANSFORM_ACTION_KIND,
            }:
                candidate_id = action.get("candidate_id")
                candidate = next(
                    (
                        item
                        for item in state.candidates
                        if item.id == candidate_id
                        and item.source_run_id != invocation.run_id
                    ),
                    None,
                )
                if candidate is None:
                    reject(run, index, "typed_gate_reference_invalid")
                    return
                oracle_preissue_id = action.get("oracle_preissue_id")
                history = state.extra.get(
                    MANAGED_ORACLE_PREISSUE_STATE_KEY
                )
                raw_preissue = (
                    history.get(oracle_preissue_id)
                    if type(history) is dict
                    and type(oracle_preissue_id) is str
                    else None
                )
                try:
                    preissue = (
                        validate_managed_oracle_preissue_public_record(
                            raw_preissue
                        )
                    )
                except ManagedOraclePreissueError:
                    reject(run, index, "typed_gate_oracle_preissue_invalid")
                    return
                expected_preissue_kind = (
                    MANAGED_ORACLE_PREISSUE_CRYPTO
                    if kind
                    == MANAGED_CRYPTO_METAMORPHIC_ACTION_KIND
                    else MANAGED_ORACLE_PREISSUE_MISC
                )
                if (
                    preissue.get("preissue_id")
                    != oracle_preissue_id
                    or preissue.get("kind") != expected_preissue_kind
                    or preissue.get("status") != "unused"
                    or preissue.get("issuer") != "operator"
                    or preissue.get("configuration_epoch")
                    != state.configuration_epoch
                    or preissue.get("source_manifest_sha256")
                    != state.metadata.get("source_manifest_sha256")
                    or preissue.get("image_digest")
                    != self.engine.config.runtime.image_digest
                    or run.base_revision
                    <= int(preissue.get("issue_revision", 0))
                ):
                    reject(run, index, "typed_gate_oracle_preissue_invalid")
                    return
                reference = {
                    "candidate_id": candidate.id,
                    "oracle_preissue_id": oracle_preissue_id,
                }
                if kind == MANAGED_CRYPTO_METAMORPHIC_ACTION_KIND:
                    runtime = action.get("runtime")
                    if runtime not in {"python", "sage"}:
                        reject(run, index, "typed_gate_action_invalid")
                        return
                    reference["runtime"] = runtime

            request = {
                "schema_version": 1,
                "action_kind": kind,
                "configuration_epoch": state.configuration_epoch,
                "source_builder_run_id": invocation.run_id,
                "artifact_bindings": artifact_bindings,
                **reference,
            }
            experiment_id = _stable_id(
                "E",
                identity.key,
                canonical_wave.id,
                invocation.run_id,
                index,
                "typed-gate-v1",
            )
            existing = next(
                (
                    item
                    for item in state.experiments
                    if item.id == experiment_id
                ),
                None,
            )
            artifact_ids = [
                str(binding["artifact_id"])
                for binding in artifact_bindings.values()
            ]
            if kind == MANAGED_DATA_TRANSCRIPT_ACTION_KIND:
                private_recipe_ids = set(artifact_ids)
                private_recipes = [
                    artifact
                    for artifact in state.artifacts
                    if artifact.id in private_recipe_ids
                ]
                if (
                    len(private_recipes) != 1
                    or private_recipes[0].source_run_id
                    != invocation.run_id
                ):
                    raise ManagedError(
                        "managed data transcript recipe lost its "
                        "private artifact binding"
                    )
                private_recipes[0].extra[
                    "context_visibility"
                ] = "engine_private"
            command = f"{_MANAGED_TYPED_GATE_ENGINE_COMMAND}:{kind}"
            if existing is not None:
                if (
                    existing.command != command
                    or existing.hypothesis_ids != resolved_hypotheses
                    or existing.artifact_ids != artifact_ids
                    or existing.extra.get("managed_typed_gate_request")
                    != request
                ):
                    raise ManagedError(
                        "managed typed gate idempotency collision: "
                        f"{experiment_id}"
                    )
                registered_ids.append(existing.id)
                return
            state.experiments.append(
                Experiment(
                    id=experiment_id,
                    hypothesis_ids=resolved_hypotheses,
                    command=command,
                    expected_observation=(
                        "the engine-owned category gate returns its exact "
                        "deterministic passing verdict"
                    ),
                    keep_if=(
                        "the engine-owned typed gate result passes without "
                        "granting automatic submission authority"
                    ),
                    drop_if=(
                        "the typed gate rejects, fails, or reports a "
                        "non-passing deterministic verdict"
                    ),
                    timeout_seconds=int(
                        reference.get(
                            "timeout_seconds",
                            self.engine._budget_command_timeout(
                                state,
                                self.engine.config.runtime.command_timeout_s,
                            ),
                        )
                    ),
                    resource_class="standard",
                    kind=(
                        ExperimentKind.STRATEGIC
                        if resolved_hypotheses
                        else ExperimentKind.PROBE
                    ),
                    status=ExperimentStatus.REGISTERED,
                    source_run_id=invocation.run_id,
                    artifact_ids=artifact_ids,
                    extra={
                        "managed_contract_version": 2,
                        "managed_action_kind": kind,
                        "engine_executor": (
                            _MANAGED_TYPED_GATE_ENGINE_EXECUTOR
                        ),
                        "configuration_epoch": state.configuration_epoch,
                        "managed_typed_gate_request": request,
                    },
                )
            )
            registered_ids.append(experiment_id)

        self.engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )
        return ManagedTypedGateRegistrationOutcome(
            experiment_ids=tuple(registered_ids),
            rejection_code=(
                rejection_codes[0] if rejection_codes else None
            ),
        )

    def _checkpoint(
        self,
        identity: ChallengeIdentity,
        session_id: str,
        cycle_id: str,
        *,
        note: str | None,
        failure_reason_code: str | None = None,
        failure_stage: str | None = None,
    ) -> ChallengeState:
        current = self.engine.store.load(identity)
        session = self._require_epoch(current, session_id)
        cycle = next(item for item in current.cycles if item.id == cycle_id)
        if (failure_reason_code is None) != (failure_stage is None):
            raise ManagedError(
                "failure checkpoint requires both reason_code and stage"
            )
        failure_capsule = (
            build_failure_capsule(
                current,
                session_id=session_id,
                cycle_id=cycle_id,
                reason_code=failure_reason_code,
                stage=failure_stage,
                state_revision_after=current.revision + 1,
            )
            if failure_reason_code is not None
            and failure_stage is not None
            else None
        )
        if (
            failure_capsule is not None
            and failure_capsule.state_revision_after
            != current.revision + 1
        ):
            raise ManagedError(
                "failure capsule does not bind the pending checkpoint "
                "revision"
            )
        checkpoint_id = _stable_id(
            "CP", identity.key, session_id, cycle_id
        )
        selected = set(cycle.selected_action_ids)
        selected_experiments = [
            item for item in current.experiments if item.id in selected
        ]
        receipt_ids = [
            item.id
            for item in current.receipts
            if item.experiment_id in selected
        ]
        cycle_run_ids = {
            item.id
            for item in current.runs
            if item.session_id == session_id
            and item.cycle_id == cycle_id
        }
        observation_ids = [
            item.id
            for item in current.facts
            if item.kind is FactKind.OBSERVATION
            and item.source_run_id in cycle_run_ids
        ]
        artifact_ids = list(
            dict.fromkeys(
                artifact_id
                for item in selected_experiments
                for artifact_id in item.artifact_ids
            )
        )
        next_actions = checkpoint_action_references(
            item
            for item in current.experiments
            if item.status is ExperimentStatus.REGISTERED
        )[:10]
        do_not_repeat = checkpoint_action_references(
            item
            for item in selected_experiments
            if item.status
            in {
                ExperimentStatus.COMPLETED,
                ExperimentStatus.AWAITING_EVALUATION,
                ExperimentStatus.FAILED,
            }
        )
        checkpoint = Checkpoint(
            id=checkpoint_id,
            session_id=session_id,
            cycle_id=cycle_id,
            active_goal_id=current.active_goal_id,
            open_hypothesis_ids=[
                item.id
                for item in current.hypotheses
                if item.status in ACTIVE_HYPOTHESIS_STATUSES
            ],
            observation_fact_ids=observation_ids,
            next_actions=next_actions,
            do_not_repeat=do_not_repeat,
            artifact_ids=artifact_ids,
            receipt_ids=receipt_ids,
            note=note,
            extra=checkpoint_action_projection_metadata(),
            failure_capsule=failure_capsule,
        )

        def apply(state: ChallengeState) -> None:
            active_session = self._require_epoch(state, session_id)
            target_cycle = next(
                item for item in state.cycles if item.id == cycle_id
            )
            if not any(item.id == checkpoint_id for item in state.checkpoints):
                state.checkpoints.append(checkpoint)
            target_cycle.checkpoint_id = checkpoint_id
            target_cycle.phase = "completed"
            target_cycle.completed_at = utc_now()
            if target_cycle.wave_id is not None:
                wave = next(
                    item
                    for item in state.waves
                    if item.id == target_cycle.wave_id
                )
                statuses = {
                    run.status
                    for run in state.runs
                    if run.id in wave.role_run_ids.values()
                }
                wave.status = (
                    "completed"
                    if failure_reason_code is None
                    and statuses == {RunStatus.COMPLETED}
                    else "invalid"
                )
                wave.reduced_at = utc_now()
            for run in state.runs:
                if (
                    run.session_id == session_id
                    and run.id not in active_session.run_ids
                ):
                    active_session.run_ids.append(run.id)

        return self.engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )

    def _execute_selected_actions(
        self,
        identity: ChallengeIdentity,
        selected: Sequence[str],
        *,
        record_stall: bool = True,
    ) -> ChallengeState:
        """Run role lanes, then evaluate stall once for the bounded wave."""

        if not selected:
            return self.engine.store.load(identity)
        state = self.engine.store.load(identity)
        experiments = {
            item.id: item
            for item in state.experiments
            if item.id in set(selected)
        }
        if set(experiments) != set(selected):
            missing = sorted(set(selected) - set(experiments))
            raise ManagedError(
                "selected managed experiments disappeared: "
                + ", ".join(missing)
            )
        typed_gate_experiments = [
            item
            for item in experiments.values()
            if item.extra.get("engine_executor")
            == _MANAGED_TYPED_GATE_ENGINE_EXECUTOR
        ]
        if typed_gate_experiments:
            if len(selected) != 1 or len(typed_gate_experiments) != 1:
                raise ManagedError(
                    "managed typed gate dispatch requires exactly one "
                    "canonical experiment"
                )
            try:
                completed = self._execute_typed_gate_experiment(
                    identity,
                    typed_gate_experiments[0].id,
                )
            except Exception as error:
                completed = (
                    self._terminalize_typed_gate_dispatch_rejection(
                        identity,
                        typed_gate_experiments[0].id,
                        error,
                    )
                )
            return (
                self.engine._record_stall_if_needed(completed)
                if record_stall
                else completed
            )
        proof_experiments = [
            item
            for item in experiments.values()
            if item.kind is ExperimentKind.PROOF
        ]
        if proof_experiments:
            if (
                len(selected) != 1
                or len(proof_experiments) != 1
                or proof_experiments[0].proof_recipe is None
            ):
                raise ManagedError(
                    "managed proof dispatch requires exactly one typed recipe"
                )
            self.engine.execute_proof_experiment(
                identity,
                proof_experiments[0].id,
                _session_owned=True,
            )
            completed = self.engine.store.load(identity)
            return (
                self.engine._record_stall_if_needed(completed)
                if record_stall
                else completed
            )
        run_roles = {item.id: item.role for item in state.runs}
        lanes: dict[str, list[str]] = {}
        for experiment_id in selected:
            experiment = experiments[experiment_id]
            role = run_roles.get(
                experiment.source_run_id or "",
                experiment.source_run_id
                or (
                    f"adapter:{experiment.id}"
                    if experiment.extra.get("adapter_seed") is True
                    else "unknown"
                ),
            )
            lanes.setdefault(str(role), []).append(experiment_id)

        storage_admission = (
            self.engine._admit_managed_tool_action_batch_storage(
                identity,
                experiment_ids=selected,
            )
        )

        def execute_lane(experiment_ids: Sequence[str]) -> None:
            for experiment_id in experiment_ids:
                self.engine.execute_registered_experiments(
                    identity,
                    maximum=1,
                    experiment_ids=(experiment_id,),
                    _session_owned=True,
                    _automated=True,
                    # A selected action set is one bounded experiment wave.
                    # Per-action governor commits can race other lanes and
                    # freeze a valid wave at an intermediate revision.
                    _record_stall=False,
                    # The entire bounded lane set was conservatively admitted
                    # before any parallel action writer started.
                    _storage_admission=storage_admission,
                )

        try:
            if len(lanes) == 1:
                execute_lane(next(iter(lanes.values())))
            else:
                errors: list[BaseException] = []
                with ThreadPoolExecutor(
                    max_workers=len(lanes),
                    thread_name_prefix="ctfos-managed-tool",
                ) as executor:
                    futures = [
                        executor.submit(execute_lane, tuple(experiment_ids))
                        for experiment_ids in lanes.values()
                    ]
                    for future in futures:
                        try:
                            future.result()
                        except BaseException as error:
                            errors.append(error)
                if errors:
                    primary = errors[0]
                    for additional in errors[1:]:
                        primary.add_note(
                            "additional managed tool lane failed: "
                            f"{type(additional).__name__}: {additional}"
                        )
                    raise primary
        finally:
            self.engine._release_managed_tool_action_batch_storage(
                storage_admission
            )
        completed = self.engine.store.load(identity)
        return (
            self.engine._record_stall_if_needed(completed)
            if record_stall
            else completed
        )

    @staticmethod
    def _bounded_pwn_crash_failure_reason(
        verdict: str,
        reason_code: str,
    ) -> str:
        """Project one typed gate verdict into a capsule-safe identifier."""

        return bounded_pwn_crash_failure_reason(verdict, reason_code)

    @classmethod
    def _selected_pwn_crash_failure_reason(
        cls,
        state: ChallengeState,
        selected: Sequence[str],
    ) -> str | None:
        """Return a deterministic capsule reason for selected non-pass gates."""

        return selected_pwn_crash_failure_reason(state, selected)

    @staticmethod
    def _selected_typed_gate_failure_reason(
        state: ChallengeState,
        selected: Sequence[str],
    ) -> str | None:
        selected_ids = set(selected)
        for experiment in state.experiments:
            if (
                experiment.id in selected_ids
                and experiment.extra.get("engine_executor")
                == _MANAGED_TYPED_GATE_ENGINE_EXECUTOR
                and experiment.status is not ExperimentStatus.COMPLETED
            ):
                return "managed_typed_gate_nonpass"
        return None

    def _checkpoint_selected_actions(
        self,
        identity: ChallengeIdentity,
        session_id: str,
        cycle_id: str,
        wave: ManagedWave,
        selected: Sequence[str],
        *,
        note: str | None,
    ) -> ChallengeState:
        """Checkpoint selected results, making typed Pwn non-passes durable."""

        latest = self.engine.store.load(identity)
        failure_reason = self._selected_pwn_crash_failure_reason(
            latest,
            selected,
        )
        if failure_reason is None:
            failure_reason = self._selected_typed_gate_failure_reason(
                latest,
                selected,
            )
        return self._checkpoint(
            identity,
            session_id,
            cycle_id,
            note=note,
            failure_reason_code=failure_reason,
            failure_stage=(
                wave.kind.value if failure_reason is not None else None
            ),
        )

    def _finish_session(
        self,
        identity: ChallengeIdentity,
        session_id: str,
        *,
        status: SessionStatus,
        reason: str,
        challenge_target: ChallengeStatus | None = None,
    ) -> ChallengeState:
        current = self.engine.store.load(identity)

        def apply(state: ChallengeState) -> None:
            session = self._session(state, session_id)
            if session.status in {
                SessionStatus.COMPLETED,
                SessionStatus.PAUSED,
                SessionStatus.FAILED,
                SessionStatus.INTERRUPTED,
            }:
                return
            session.status = status
            session.stop_reason = reason
            session.end_revision = state.revision + 1
            session.ended_at = utc_now()
            if state.active_managed_session_id == session_id:
                state.active_managed_session_id = None
            if challenge_target is ChallengeStatus.PAUSED:
                if state.status is not ChallengeStatus.PAUSED:
                    state.resume_status = state.status
                    state.status = ChallengeStatus.PAUSED
            elif challenge_target is not None:
                state.status = challenge_target
                state.resume_status = None

        return self.engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )

    def _pause_active_session_after_preflight_block(
        self,
        identity: ChallengeIdentity,
        error: ManagedPreflightBlocked,
        *,
        expected_session_id: str | None = None,
    ) -> ChallengeState | None:
        """Close owned work when a later preflight can no longer proceed."""

        current = self.engine.store.load(identity)
        session_id = current.active_managed_session_id
        if session_id is None:
            return None
        if (
            expected_session_id is not None
            and session_id != expected_session_id
        ):
            raise ManagedError(
                "managed preflight block changed the active session"
            ) from error
        self._finish_session(
            identity,
            session_id,
            status=SessionStatus.PAUSED,
            reason=str(error),
            challenge_target=ChallengeStatus.PAUSED,
        )
        # Preserve any already-written provider result while terminalizing an
        # undispatched reservation or unfinished cycle as interrupted.
        return self.reconcile(identity)

    def cancel_session(
        self,
        identity: ChallengeIdentity,
        *,
        reason: str,
        target: ChallengeStatus,
    ) -> ChallengeState:
        if not reason.strip():
            raise ManagedError("session cancel reason is required")
        if target not in {
            ChallengeStatus.PAUSED,
            ChallengeStatus.NEEDS_HUMAN,
        }:
            raise ManagedError("session cancel target must be PAUSED or NEEDS_HUMAN")
        state = self.engine.store.load(identity)
        if state.active_managed_session_id is None:
            raise ManagedError("there is no active managed session")
        return self._finish_session(
            identity,
            state.active_managed_session_id,
            status=SessionStatus.PAUSED,
            reason=reason,
            challenge_target=target,
        )

    def reconcile(self, identity: ChallengeIdentity) -> ChallengeState:
        """Terminalize orphan managed runs conservatively as interrupted."""

        state = self.engine.store.load(identity)
        orphaned = [
            run
            for run in state.runs
            if run.origin is RunOrigin.MANAGED_MODEL
            and run.status not in _TERMINAL_RUN_STATUSES
        ]
        root = self.engine.store.challenge_paths(identity).root
        terminal_paths: dict[
            str,
            tuple[
                str,
                str,
                str,
                RunStatus,
                bool,
                dict[str, Any],
            ],
        ] = {}
        for run in orphaned:
            paths = self.engine.store.run_paths(identity, run_id=run.id)
            if not paths.root.exists():
                paths.root.mkdir(parents=True, mode=0o700)
            paths.raw.mkdir(mode=0o700, exist_ok=True)
            request_was_missing = not paths.request.exists()
            result_was_missing = not paths.result.exists()
            validation_was_missing = not paths.validation.exists()
            if request_was_missing:
                atomic_write_json(
                    paths.request,
                    {
                        "schema_version": RUN_ENVELOPE_SCHEMA_VERSION,
                        **identity.to_dict(),
                        "run_id": run.id,
                        "base_revision": run.base_revision,
                        "kind": "managed-recovery",
                        "role": run.role,
                        "configuration_epoch": run.configuration_epoch,
                        "created_at": run.created_at,
                    },
                )
            recovered_status = RunStatus.INTERRUPTED
            recovered_from_result = False
            result_record: Mapping[str, Any] | None = None
            recovery_document_errors: list[str] = [
                label
                for missing, label in (
                    (request_was_missing, "request.missing"),
                    (result_was_missing, "result.missing"),
                    (validation_was_missing, "validation.missing"),
                )
                if missing
            ]

            def require_document_fields(
                label: str,
                record: Mapping[str, Any],
                expected: Mapping[str, Any],
            ) -> None:
                for field, value in expected.items():
                    observed = record.get(field)
                    if (
                        type(observed) is not type(value)
                        or observed != value
                    ):
                        recovery_document_errors.append(
                            f"{label}.{field}_mismatch"
                        )

            try:
                request_record = read_json(paths.request)
                if not isinstance(request_record, Mapping):
                    recovery_document_errors.append(
                        "request.not_an_object"
                    )
                else:
                    recovery_document_errors.extend(
                        managed_request_binding_errors(
                            request_record,
                            identity=identity,
                            run=run,
                        )
                    )
            except (OSError, StrictJSONError, TypeError, ValueError):
                recovery_document_errors.append("request.invalid_json")

            if paths.result.exists() and paths.validation.exists():
                try:
                    loaded_result_record = read_json(paths.result)
                    validation_record = read_json(paths.validation)
                    if not isinstance(loaded_result_record, Mapping):
                        recovery_document_errors.append(
                            "result.not_an_object"
                        )
                    else:
                        result_record = loaded_result_record
                        require_document_fields(
                            "result",
                            result_record,
                            {
                                "schema_version": (
                                    WORKER_RESULT_SCHEMA_VERSION
                                ),
                                "contest_id": identity.contest_id,
                                "category": identity.category,
                                "challenge_id": identity.challenge_id,
                                "run_id": run.id,
                                "base_revision": run.base_revision,
                            },
                        )
                        if (
                        "configuration_epoch" in result_record
                            and (
                                type(
                                    result_record.get(
                                        "configuration_epoch"
                                    )
                                )
                                is not int
                                or result_record.get(
                                    "configuration_epoch"
                                )
                                != run.configuration_epoch
                            )
                        ):
                            recovery_document_errors.append(
                                "result.configuration_epoch_mismatch"
                            )
                        if (
                            "role" in result_record
                            and result_record.get("role") != run.role
                        ):
                            recovery_document_errors.append(
                                "result.role_mismatch"
                            )
                        expected_contract_version = run.extra.get(
                            "contract_version"
                        )
                        if (
                            "role_contract_version" in result_record
                            and type(expected_contract_version) is int
                            and (
                                type(
                                    result_record.get(
                                        "role_contract_version"
                                    )
                                )
                                is not int
                                or result_record.get(
                                    "role_contract_version"
                                )
                                != expected_contract_version
                            )
                        ):
                            recovery_document_errors.append(
                                "result.contract_version_mismatch"
                            )
                        if "attempt_count" in result_record and (
                            type(result_record.get("attempt_count")) is not int
                            or result_record.get("attempt_count") < 0
                        ):
                            recovery_document_errors.append(
                                "result.attempt_count_invalid"
                            )
                    if not isinstance(validation_record, Mapping):
                        recovery_document_errors.append(
                            "validation.not_an_object"
                        )
                    else:
                        require_document_fields(
                            "validation",
                            validation_record,
                            {
                                "run_id": run.id,
                                "base_revision": run.base_revision,
                            },
                        )
                        for field, value in (
                            ("contest_id", identity.contest_id),
                            ("category", identity.category),
                            ("challenge_id", identity.challenge_id),
                            (
                                "configuration_epoch",
                                run.configuration_epoch,
                            ),
                        ):
                            if (
                                field in validation_record
                                and (
                                    type(validation_record.get(field))
                                    is not type(value)
                                    or validation_record.get(field) != value
                                )
                            ):
                                recovery_document_errors.append(
                                    f"validation.{field}_mismatch"
                                )
                        if type(validation_record.get("ok")) is not bool:
                            recovery_document_errors.append(
                                "validation.ok_invalid"
                            )

                    if (
                        isinstance(result_record, Mapping)
                        and isinstance(validation_record, Mapping)
                    ):
                        terminal = result_record.get("managed_terminal")
                        status_value = (
                            terminal.get("status")
                            if isinstance(terminal, Mapping)
                            else result_record.get("status")
                            if result_record.get(
                                "provisional_managed_result"
                            )
                            is True
                            else None
                        )
                        try:
                            candidate_status = RunStatus(
                                str(status_value)
                            )
                        except ValueError:
                            recovery_document_errors.append(
                                "result.terminal_status_invalid"
                            )
                        else:
                            if candidate_status not in _TERMINAL_RUN_STATUSES:
                                recovery_document_errors.append(
                                    "result.terminal_status_invalid"
                                )
                            elif (
                                validation_record.get("ok") is True
                            ) != (
                                candidate_status is RunStatus.COMPLETED
                            ):
                                recovery_document_errors.append(
                                    "validation.result_status_mismatch"
                                )
                            elif not recovery_document_errors:
                                recovered_status = candidate_status
                                recovered_from_result = True
                except (OSError, StrictJSONError, TypeError, ValueError):
                    recovery_document_errors.append(
                        "result_or_validation.invalid_json"
                    )
            if not paths.result.exists():
                self.engine.store.write_run_result(
                    identity,
                    run.id,
                    {
                        "status": "interrupted",
                        "base_revision": run.base_revision,
                        "artifacts": [],
                        "flag_candidates": [],
                        "recovery": "provider completion is unknown",
                    },
                )
            if not paths.validation.exists():
                self.engine.store.write_run_validation(
                    identity,
                    run.id,
                    {
                        "ok": False,
                        "base_revision": run.base_revision,
                        "errors": ["run interrupted before canonical commit"],
                        "error_type": "ManagedRecovery",
                    },
                )

            provider_path = paths.root / "provider.json"
            provider_record: dict[str, Any] = {}
            provider_record_existed = provider_path.exists()
            if provider_record_existed:
                try:
                    loaded_provider_record = read_json(provider_path)
                except (OSError, StrictJSONError) as error:
                    raise ManagedError(
                        f"managed provider recovery record is invalid: {run.id}"
                    ) from error
                if not isinstance(loaded_provider_record, Mapping):
                    raise ManagedError(
                        f"managed provider recovery record is invalid: {run.id}"
                    )
                provider_record = dict(loaded_provider_record)
                recorded_schema_version = provider_record.get(
                    "schema_version"
                )
                if (
                    recorded_schema_version is not None
                    and (
                        type(recorded_schema_version) is not int
                        or recorded_schema_version != 1
                    )
                ):
                    raise ManagedError(
                        "managed provider recovery schema version is invalid: "
                        f"{run.id}"
                    )
                recorded_run_id = provider_record.get("run_id")
                if recorded_run_id is not None and (
                    type(recorded_run_id) is not str
                    or recorded_run_id != run.id
                ):
                    raise ManagedError(
                        f"managed provider recovery run id mismatch: {run.id}"
                    )
                recorded_configuration_epoch = provider_record.get(
                    "configuration_epoch"
                )
                if (
                    recorded_configuration_epoch is not None
                    and (
                        type(recorded_configuration_epoch) is not int
                        or recorded_configuration_epoch
                        != run.configuration_epoch
                    )
                ):
                    raise ManagedError(
                        "managed provider recovery configuration epoch "
                        f"mismatch: {run.id}"
                    )

                existing_provider_status = provider_record.get("status")
                terminal_provider_statuses = {
                    item.value for item in _TERMINAL_RUN_STATUSES
                }
                if (
                    type(existing_provider_status) is not str
                    or existing_provider_status
                    not in {"running", *terminal_provider_statuses}
                ):
                    recovery_document_errors.append(
                        "provider.status_invalid"
                    )
                    recovered_status = RunStatus.INTERRUPTED
                    recovered_from_result = False
                elif (
                    existing_provider_status != "running"
                    and existing_provider_status != recovered_status.value
                ):
                    recovery_document_errors.append(
                        "provider.result_status_mismatch"
                    )
                    recovered_status = RunStatus.INTERRUPTED
                    recovered_from_result = False

            recorded_started = provider_record.get("provider_started")
            if recorded_started is not None and type(recorded_started) is not bool:
                raise ManagedError(
                    f"managed provider recovery start marker is invalid: {run.id}"
                )
            provider_started = (
                recorded_started
                if type(recorded_started) is bool
                else provider_record.get("status") == "running"
                and isinstance(provider_record.get("started_at"), str)
            )
            if provider_record_existed:
                started_at = provider_record.get("started_at")
                if (
                    provider_started
                    and (
                        not isinstance(started_at, str)
                        or not started_at
                    )
                ) or (not provider_started and started_at is not None):
                    recovery_document_errors.append(
                        "provider.start_binding_invalid"
                    )
                    recovered_status = RunStatus.INTERRUPTED
                    recovered_from_result = False
                    provider_started = False

            def recovered_seconds(field: str) -> float | None:
                value = provider_record.get(field)
                if value is None:
                    return None
                if (
                    type(value) not in {int, float}
                    or not math.isfinite(float(value))
                    or float(value) < 0
                ):
                    raise ManagedError(
                        "managed provider recovery timing is invalid: "
                        f"{run.id}:{field}"
                    )
                return float(value)

            timing_metadata = {
                field: recovered_seconds(field)
                for field in (
                    "provider_wait_seconds",
                    "provider_process_span_seconds",
                    "model_call_wall_seconds",
                )
            }
            attempt_count = provider_record.get("attempt_count")
            result_attempt_count = (
                result_record.get("attempt_count")
                if isinstance(result_record, Mapping)
                else None
            )
            if (
                attempt_count is not None
                and result_attempt_count is not None
                and (
                    type(result_attempt_count) is not int
                    or type(attempt_count) is not int
                    or attempt_count != result_attempt_count
                )
            ):
                recovery_document_errors.append(
                    "provider.result_attempt_count_mismatch"
                )
                recovered_status = RunStatus.INTERRUPTED
                recovered_from_result = False
                attempt_count = None
            if (
                attempt_count is None
                and recovered_from_result
                and result_record is not None
            ):
                attempt_count = result_record.get("attempt_count")
            if attempt_count is not None and (
                type(attempt_count) is not int or attempt_count < 0
            ):
                raise ManagedError(
                    f"managed provider recovery attempt count is invalid: {run.id}"
                )
            existing_provider_status = provider_record.get("status")
            existing_finished_at = provider_record.get("finished_at")
            provider_completed_at = (
                existing_finished_at
                if existing_provider_status != "running"
                and isinstance(existing_finished_at, str)
                and existing_finished_at
                else utc_now()
            )
            provider_record.update(
                {
                    "schema_version": 1,
                    "status": recovered_status.value,
                    "run_id": run.id,
                    "configuration_epoch": run.configuration_epoch,
                    "started_at": (
                        provider_record.get("started_at")
                        if provider_started
                        else None
                    ),
                    "finished_at": provider_completed_at,
                    "provider_started": provider_started,
                    "provider_wait_seconds": timing_metadata[
                        "provider_wait_seconds"
                    ],
                    "provider_process_span_seconds": timing_metadata[
                        "provider_process_span_seconds"
                    ],
                    "model_call_wall_seconds": timing_metadata[
                        "model_call_wall_seconds"
                    ],
                    "attempt_count": attempt_count,
                    "recovered_by": "managed_reconcile",
                }
            )
            atomic_write_json(provider_path, provider_record)
            recovery_extra: dict[str, Any] = {
                "provider_started": provider_started,
                "provider_outcome_status": recovered_status.value,
                "provider_completed_at": provider_completed_at,
                "request_sha256": sha256_file(paths.request),
                "result_sha256": sha256_file(paths.result),
                "validation_sha256": sha256_file(paths.validation),
            }
            if attempt_count is not None:
                recovery_extra["attempt_count"] = attempt_count
            if recovery_document_errors:
                recovery_extra[
                    "recovery_document_validation_errors"
                ] = list(dict.fromkeys(recovery_document_errors))
            recovery_extra.update(
                {
                    field: value
                    for field, value in timing_metadata.items()
                    if value is not None
                }
            )
            terminal_paths[run.id] = (
                str(paths.request.relative_to(root)),
                str(paths.result.relative_to(root)),
                str(paths.validation.relative_to(root)),
                recovered_status,
                recovered_from_result,
                recovery_extra,
            )

        if terminal_paths:
            current = self.engine.store.load(identity)

            def apply(recovered: ChallengeState) -> None:
                for run in recovered.runs:
                    paths = terminal_paths.get(run.id)
                    if paths is None or run.status in _TERMINAL_RUN_STATUSES:
                        continue
                    (
                        request_path,
                        result_path,
                        validation_path,
                        recovered_status,
                        recovered_from_result,
                        recovery_extra,
                    ) = paths
                    stale = (
                        run.configuration_epoch
                        != recovered.configuration_epoch
                        or run.session_id
                        != recovered.active_managed_session_id
                        or recovered.status in _STOP_STATUSES
                    )
                    run.status = (
                        RunStatus.INTERRUPTED
                        if stale
                        else recovered_status
                    )
                    run.request_path = request_path
                    run.result_path = result_path
                    run.validation_path = validation_path
                    run.extra["reconciled_at"] = utc_now()
                    run.extra["semantic_merge"] = False
                    run.extra["provisional_managed_terminal"] = True
                    run.extra["recovered_from_durable_result"] = (
                        recovered_from_result
                    )
                    run.extra.update(recovery_extra)

            state = self.engine.store.update(
                identity,
                apply,
                expected_revision=current.revision,
            )

        unfinished_cycle_ids = {
            cycle.id
            for cycle in state.cycles
            if cycle.completed_at is None
        }
        active_session_id = state.active_managed_session_id
        if (
            active_session_id is not None
            and state.status
            in {
                ChallengeStatus.READY_TO_SUBMIT,
                ChallengeStatus.SOLVED,
                ChallengeStatus.ABANDONED,
            }
            and not any(
                cycle.session_id == active_session_id
                and cycle.completed_at is None
                for cycle in state.cycles
            )
        ):
            return self._finish_session(
                identity,
                active_session_id,
                status=SessionStatus.COMPLETED,
                reason=(
                    "managed recovery finalized a terminal challenge after "
                    "its durable checkpoint"
                ),
            )
        if not unfinished_cycle_ids:
            return state
        current = self.engine.store.load(identity)

        def interrupt_unfinished(recovered: ChallengeState) -> None:
            affected_sessions: set[str] = set()
            for cycle in recovered.cycles:
                if (
                    cycle.id not in unfinished_cycle_ids
                    or cycle.completed_at is not None
                ):
                    continue
                cycle.phase = "interrupted"
                cycle.completed_at = utc_now()
                affected_sessions.add(cycle.session_id)
                if cycle.wave_id is not None:
                    wave = next(
                        (
                            item
                            for item in recovered.waves
                            if item.id == cycle.wave_id
                        ),
                        None,
                    )
                    if wave is not None and wave.reduced_at is None:
                        wave.status = "interrupted"
                        wave.reduced_at = utc_now()
            for session in recovered.sessions:
                if (
                    session.id in affected_sessions
                    and session.status
                    in {SessionStatus.CREATED, SessionStatus.RUNNING}
                ):
                    session.status = SessionStatus.INTERRUPTED
                    session.stop_reason = (
                        "managed recovery found an unfinished durable cycle"
                    )
                    session.end_revision = recovered.revision + 1
                    session.ended_at = utc_now()
            if recovered.active_managed_session_id in affected_sessions:
                recovered.active_managed_session_id = None
                if recovered.status not in {
                    ChallengeStatus.READY_TO_SUBMIT,
                    ChallengeStatus.SOLVED,
                    ChallengeStatus.ABANDONED,
                }:
                    if recovered.status is not ChallengeStatus.PAUSED:
                        recovered.resume_status = recovered.status
                    recovered.status = ChallengeStatus.PAUSED

        return self.engine.store.update(
            identity,
            interrupt_unfinished,
            expected_revision=current.revision,
        )

    def reconcile_explicit(
        self,
        identity: ChallengeIdentity,
    ) -> tuple[ChallengeState, ChallengeState]:
        """Reconcile one operator-selected challenge only while it is idle."""

        paths = self.engine.store.challenge_paths(identity)
        lock = ChallengeLock(paths.runtime / "session.lock", timeout=0)
        try:
            lock.acquire()
        except LockTimeout as error:
            raise SessionAlreadyRunning(
                f"another session already owns {identity.key}"
            ) from error
        try:
            before = self.engine.store.read_snapshot(identity)
            return before, self.reconcile(identity)
        finally:
            lock.release()

    def _checkpoint_invalid_cycle(
        self,
        identity: ChallengeIdentity,
        session_id: str,
        cycle_id: str,
        *,
        reason_code: str,
        reason: str,
        note: str | None,
    ) -> ChallengeState:
        """Preserve a failed model attempt and let the next cycle repair it."""

        checkpoint_note = _bounded_checkpoint_note(
            f"{reason_code}: {reason}",
            note,
        )
        self._mark_action_selection(
            identity,
            session_id,
            cycle_id,
            (),
        )
        current = self.engine.store.load(identity)
        cycle = next(
            item for item in current.cycles if item.id == cycle_id
        )
        if cycle.wave_id is None:
            stage = "captain"
        else:
            wave = next(
                item
                for item in current.waves
                if item.id == cycle.wave_id
            )
            stage = wave.kind.value
        state = self._checkpoint(
            identity,
            session_id,
            cycle_id,
            note=checkpoint_note,
            failure_reason_code=reason_code,
            failure_stage=stage,
        )
        if state.status in _STOP_STATUSES:
            target = (
                state.status
                if state.status
                in {
                    ChallengeStatus.PAUSED,
                    ChallengeStatus.NEEDS_HUMAN,
                }
                else None
            )
            return self._finish_session(
                identity,
                session_id,
                status=SessionStatus.PAUSED,
                reason=reason,
                challenge_target=target,
            )
        return state

    def _run_cycle_owned(
        self,
        identity: ChallengeIdentity,
        *,
        session_id: str | None,
        note: str | None,
        thread_continuity_policy: str,
    ) -> ChallengeState:
        self.engine._recover_session_boundary(identity)
        reconcile_workspace_publishes(self.engine, identity)
        self.reconcile(identity)
        self._retire_stale_registered_managed_remote_actions(identity)
        self.require_preflight(identity, session_id=session_id)
        state, selected_session = self._reserve_session(
            identity,
            session_id,
            thread_continuity_policy=thread_continuity_policy,
        )
        try:
            state = self.engine.synchronize_managed_adapter_seed_plan(
                identity,
                selected_session,
            )
            state, cycle = self._reserve_cycle(
                identity,
                selected_session,
            )
            cartography_actions = self._initial_cartography_actions(state)
            if cartography_actions:
                self._mark_action_selection(
                    identity,
                    selected_session,
                    cycle.id,
                    cartography_actions,
                )
                self.require_preflight(
                    identity,
                    session_id=selected_session,
                )
                self._execute_selected_actions(
                    identity,
                    cartography_actions,
                    # These bounded seeds form one pre-model evidence batch.
                    # Let the Captain inspect the complete batch before any
                    # governor decision can stop the managed session.
                    record_stall=False,
                )
                self._rebase_created_run(
                    identity,
                    selected_session,
                    cycle.captain_run_id,
                )
            self.require_preflight(
                identity,
                session_id=selected_session,
            )
            captain_resume_thread = self._resume_thread_for_reserved_run(
                identity,
                cycle.captain_run_id,
            )
            captain = self.engine.run_role(
                identity,
                Role.CAPTAIN,
                prefix=f"managed-{cycle.ordinal}-captain",
                instruction=(
                    "Select exactly one next stage and maintain one active "
                    "goal. Register only discriminating actions. A candidate "
                    "is not proof."
                ),
                _session_owned=True,
                _automated=True,
                _reserved_run_id=cycle.captain_run_id,
                _managed_workspace=True,
                _resume_thread_id=captain_resume_thread,
            )
            if not captain.completed or not captain.validation.valid:
                reason_code, reason = _captain_failure_checkpoint_reason(
                    captain
                )
                return self._checkpoint_invalid_cycle(
                    identity,
                    selected_session,
                    cycle.id,
                    reason_code=reason_code,
                    reason=reason,
                    note=note,
                )
            latest = self.engine.store.load(identity)
            self._require_epoch(latest, selected_session)
            if latest.status in _STOP_STATUSES:
                target = (
                    latest.status
                    if latest.status
                    in {
                        ChallengeStatus.PAUSED,
                        ChallengeStatus.NEEDS_HUMAN,
                    }
                    else None
                )
                return self._finish_session(
                    identity,
                    selected_session,
                    status=SessionStatus.PAUSED,
                    reason=f"Captain selected {latest.status.value}",
                    challenge_target=target,
                )
            frontier_issue = self._frontier_routing_issue(
                latest,
                captain.output,
            )
            if frontier_issue is not None:
                return self._checkpoint_invalid_cycle(
                    identity,
                    selected_session,
                    cycle.id,
                    reason_code="frontier_routing_invalid",
                    reason=frontier_issue,
                    note=note,
                )
            wave_name = self._wave_name(captain.output)
            try:
                self._bind_captain_registered_experiment(
                    identity,
                    selected_session,
                    cycle.id,
                    captain.output,
                    next_stage=wave_name,
                )
            except ManagedRegisteredExperimentReferenceError as error:
                return self._checkpoint_invalid_cycle(
                    identity,
                    selected_session,
                    cycle.id,
                    reason_code="registered_action_reference_invalid",
                    reason=str(error),
                    note=note,
                )
            try:
                _state, wave, role_runs = self._reserve_wave(
                    identity,
                    selected_session,
                    cycle.id,
                    wave_name,
                    enforce_budget_guard=True,
                )
            except ManagedWaveBudgetInsufficient as blocked:
                reason = (
                    "Captain evidence was preserved, but the complete "
                    "three-role wave and deterministic action/checkpoint "
                    "reserve did not fit the remaining challenge budget "
                    f"(remaining_ms="
                    f"{blocked.audit.get('remaining_budget_ms')}, "
                    f"minimum_required_ms="
                    f"{blocked.audit.get('minimum_required_ms')})."
                )
                self._checkpoint_invalid_cycle(
                    identity,
                    selected_session,
                    cycle.id,
                    reason_code="insufficient_budget_for_wave",
                    reason=reason,
                    note=note,
                )
                return self._finish_session(
                    identity,
                    selected_session,
                    status=SessionStatus.PAUSED,
                    reason=reason,
                    challenge_target=ChallengeStatus.PAUSED,
                )
            self.require_preflight(
                identity,
                session_id=selected_session,
            )
            wave_resume_threads = {
                role: self._resume_thread_for_reserved_run(
                    identity,
                    run_id,
                )
                for role, run_id in role_runs.items()
            }
            outcome = self.engine.run_wave(
                identity,
                wave_name,
                _session_owned=True,
                _automated=True,
                _reserved_run_ids=role_runs,
                _semantic_barrier=True,
                _managed_workspace=True,
                _resume_thread_ids=wave_resume_threads,
                # The managed cycle's bounded evidence unit includes the
                # selected tool actions.  Evaluating the governor here can
                # mark the challenge STALLED before those actions run, and
                # the following preflight would then block the evidence that
                # could resolve the stall.
                _record_stall=False,
            )
            latest = self.engine.store.load(identity)
            self._require_epoch(latest, selected_session)
            run_statuses = {
                run.id: run.status
                for run in latest.runs
                if run.id in wave.role_run_ids.values()
            }
            if (
                len(run_statuses) != 3
                or any(
                    status is not RunStatus.COMPLETED
                    for status in run_statuses.values()
                )
            ):
                return self._checkpoint_invalid_cycle(
                    identity,
                    selected_session,
                    cycle.id,
                    reason_code="analysis_wave_invalid",
                    reason=(
                        "analysis wave was invalid; provisional results were "
                        "preserved"
                    ),
                    note=note,
                )
            publish_outcome = self._apply_builder_publishes(
                identity,
                wave,
                outcome.results,
            )
            if publish_outcome.rejection is not None:
                return self._checkpoint_invalid_cycle(
                    identity,
                    selected_session,
                    cycle.id,
                    reason_code="builder_publish_rejected",
                    reason=(
                        "Builder artifact publication proposal was rejected"
                    ),
                    note=note,
                )
            self._register_pwn_crash_actions(
                identity,
                wave,
                outcome.results,
            )
            typed_gate_outcome = self._register_typed_gate_actions(
                identity,
                wave,
                outcome.results,
            )
            if typed_gate_outcome.rejection_code is not None:
                return self._checkpoint_invalid_cycle(
                    identity,
                    selected_session,
                    cycle.id,
                    reason_code="managed_typed_gate_action_rejected",
                    reason=typed_gate_outcome.rejection_code,
                    note=note,
                )
            latest = self.engine.store.load(identity)
            self._require_epoch(latest, selected_session)
            try:
                selected = self._select_actions(latest, wave)
            except ManagedRegisteredExperimentReferenceError as error:
                return self._checkpoint_invalid_cycle(
                    identity,
                    selected_session,
                    cycle.id,
                    reason_code="registered_action_reference_invalid",
                    reason=str(error),
                    note=note,
                )
            except ManagedError:
                return self._checkpoint_invalid_cycle(
                    identity,
                    selected_session,
                    cycle.id,
                    reason_code="proof_recipe_invalid",
                    reason=(
                        "proof wave did not produce exactly one valid "
                        "engine-bound replay recipe"
                    ),
                    note=note,
                )
            self._mark_action_selection(
                identity,
                selected_session,
                cycle.id,
                selected,
                append=True,
            )
            if selected:
                self.require_preflight(
                    identity,
                    session_id=selected_session,
                )
                try:
                    self._execute_selected_actions(identity, selected)
                except EngineError:
                    if wave.kind is not WaveKind.PROOF:
                        raise
                    return self._checkpoint_invalid_cycle(
                        identity,
                        selected_session,
                        cycle.id,
                        reason_code="managed_proof_execution_invalid",
                        reason=(
                            "managed proof recipe was stale, unsupported, "
                            "or did not complete its replay"
                        ),
                        note=note,
                    )
            else:
                # With no selected actions, the completed logical-role wave
                # itself is the bounded evidence unit.
                self.engine._record_stall_if_needed(
                    self.engine.store.load(identity)
                )
            state = self._checkpoint_selected_actions(
                identity,
                selected_session,
                cycle.id,
                wave,
                selected,
                note=note,
            )
            if state.status in {
                ChallengeStatus.STALLED,
                ChallengeStatus.PAUSED,
                ChallengeStatus.NEEDS_HUMAN,
            }:
                return self._finish_session(
                    identity,
                    selected_session,
                    status=SessionStatus.PAUSED,
                    reason=(
                        f"challenge reached {state.status.value} after the "
                        "bounded action wave"
                    ),
                )
            if state.status in {
                ChallengeStatus.READY_TO_SUBMIT,
                ChallengeStatus.SOLVED,
                ChallengeStatus.ABANDONED,
            }:
                return self._finish_session(
                    identity,
                    selected_session,
                    status=SessionStatus.COMPLETED,
                    reason=f"challenge reached {state.status.value}",
                )
            return state
        except KeyboardInterrupt:
            self._finish_session(
                identity,
                selected_session,
                status=SessionStatus.INTERRUPTED,
                reason="operator interrupt",
                challenge_target=ChallengeStatus.PAUSED,
            )
            raise
        except ManagedPreflightBlocked as error:
            paused = self._pause_active_session_after_preflight_block(
                identity,
                error,
                expected_session_id=selected_session,
            )
            if paused is not None:
                return paused
            raise
        except BaseException as error:
            try:
                self._finish_session(
                    identity,
                    selected_session,
                    status=SessionStatus.FAILED,
                    reason=f"{type(error).__name__}: {error}",
                    challenge_target=ChallengeStatus.NEEDS_HUMAN,
                )
                self.reconcile(identity)
            except BaseException as finish_error:
                error.add_note(
                    f"managed failure terminalization failed: {finish_error}"
                )
            if isinstance(error, ManagedError):
                raise
            if isinstance(error, Exception):
                raise ManagedError(
                    f"managed cycle failed: {error}"
                ) from error
            raise

    def run_cycle(
        self,
        identity: ChallengeIdentity,
        *,
        session_id: str | None = None,
        note: str | None = None,
        thread_continuity_policy: str = "fresh",
    ) -> ChallengeState:
        paths = self.engine.store.challenge_paths(identity)
        lock = ChallengeLock(paths.runtime / "session.lock", timeout=0)
        try:
            lock.acquire()
        except LockTimeout as error:
            raise SessionAlreadyRunning(
                f"another session already owns {identity.key}"
            ) from error
        try:
            self.engine.refresh_ingest(identity)
            try:
                return self._run_cycle_owned(
                    identity,
                    session_id=session_id,
                    note=note,
                    thread_continuity_policy=thread_continuity_policy,
                )
            except ManagedPreflightBlocked as error:
                paused = self._pause_active_session_after_preflight_block(
                    identity,
                    error,
                    expected_session_id=session_id,
                )
                if paused is not None:
                    return paused
                raise
        finally:
            lock.release()

    def run_cycles(
        self,
        identity: ChallengeIdentity,
        *,
        max_cycles: int,
        session_id: str | None = None,
        note: str | None = None,
        thread_continuity_policy: str = "fresh",
    ) -> ChallengeState:
        if max_cycles < 1:
            raise ManagedError("max_cycles must be positive")
        paths = self.engine.store.challenge_paths(identity)
        lock = ChallengeLock(paths.runtime / "session.lock", timeout=0)
        try:
            lock.acquire()
        except LockTimeout as error:
            raise SessionAlreadyRunning(
                f"another session already owns {identity.key}"
            ) from error
        selected_session = session_id
        try:
            self.engine.refresh_ingest(identity)
            for _ in range(max_cycles):
                try:
                    state = self._run_cycle_owned(
                        identity,
                        session_id=selected_session,
                        note=note,
                        thread_continuity_policy=thread_continuity_policy,
                    )
                except ManagedPreflightBlocked as error:
                    paused = (
                        self._pause_active_session_after_preflight_block(
                            identity,
                            error,
                            expected_session_id=selected_session,
                        )
                    )
                    if paused is None:
                        raise
                    return paused
                selected_session = state.active_managed_session_id
                if state.status in _STOP_STATUSES:
                    return state
            state = self.engine.store.load(identity)
            if state.active_managed_session_id is not None:
                state = self._finish_session(
                    identity,
                    state.active_managed_session_id,
                    status=SessionStatus.PAUSED,
                    reason=f"max_cycles={max_cycles} reached",
                    challenge_target=ChallengeStatus.PAUSED,
                )
            return state
        finally:
            lock.release()


__all__ = [
    "ManagedError",
    "ManagedOrchestrator",
    "ManagedPreflightBlocked",
    "PreflightReport",
]
