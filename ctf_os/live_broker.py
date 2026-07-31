"""Challenge-scoped high-level RPC used by attached Live Codex sessions.

The interactive Codex process is intentionally unable to write the canonical
state tree, execute a host shell, or connect to Docker. A required local stdio
MCP bridge exchanges bounded atomic files with a private temporary mailbox; the
model never receives that path or capability. The already-authorized parent
executes only a small set of typed operations and owns the challenge session
lock for the complete TUI lifetime.
"""

from __future__ import annotations

import errno
import hmac
import json
import math
import os
import re
import secrets
import stat
import sys
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ctf_os.knowledge import (
    DEFAULT_KNOWLEDGE_READ_BYTES,
    MAX_EXTRACTED_TEXT_BYTES,
    MAX_KNOWLEDGE_READ_BYTES,
    MAX_KNOWLEDGE_SEARCH_RESULTS,
    KnowledgeStore,
)
from ctf_os.models import (
    ChallengeIdentity,
    ChallengeStatus,
    ExperimentStatus,
    HypothesisStatus,
    Provenance,
)
from ctf_os.sandbox.daemon import CapabilityAuthority, CapabilityError
from ctf_os.sandbox.types import JobRef

if TYPE_CHECKING:
    from ctf_os.engine.challenge import ChallengeEngine


MAX_LIVE_RPC_BYTES = 1024 * 1024
MAX_INSPECT_RESULT_BYTES = 768 * 1024
MAX_INSPECT_PAGE_ITEMS = 200
MAX_INSPECT_OFFSET = 2**31 - 1
DEFAULT_INSPECT_PAGE_ITEMS = 100
MAX_MAILBOX_SCAN_ENTRIES = 4096
MAX_LIVE_SESSION_REQUESTS = 16384
MAX_LIVE_OPERATION_SECONDS = 8 * 60 * 60
MAX_LIVE_CLIENT_GRACE_SECONDS = 180
MAX_CONCURRENT_READ_ONLY_OPERATIONS = 8
LIVE_BROKER_DIRECTORY_ENV = "CTFOS_LIVE_BROKER_DIR"
LIVE_SCOPE_CAPABILITY_ENV = "CTFOS_SCOPE_CAPABILITY"
LIVE_SESSION_ENV = "CTFOS_LIVE_SESSION"
_REQUEST_NAME = re.compile(r"request-([0-9a-f]{32})\.json\Z")
_SERVER_STATUS_NAME = "server-status.json"
INSPECT_LIST_SECTIONS = (
    "goals",
    "facts",
    "hypotheses",
    "experiments",
    "progress_markers",
    "runs",
    "artifacts",
    "candidates",
    "submissions",
)
INSPECT_SECTIONS = ("summary", "state", *INSPECT_LIST_SECTIONS)
LIVE_HYPOTHESIS_STATUSES = (HypothesisStatus.OPEN.value,)
LIVE_TRANSITION_TARGETS = (
    ChallengeStatus.TRIAGING.value,
    ChallengeStatus.ACTIVE.value,
    ChallengeStatus.STALLED.value,
    ChallengeStatus.NEEDS_RESEARCH.value,
    ChallengeStatus.NEEDS_HUMAN.value,
    ChallengeStatus.PAUSED.value,
)


class LiveBrokerError(RuntimeError):
    """The Live parent broker rejected or could not complete an operation."""


def _prefer_control_error(
    primary: BaseException,
    latest: BaseException,
    *,
    label: str,
) -> BaseException:
    """Keep the first control-flow exception ahead of ordinary failures."""

    if not isinstance(latest, Exception) and isinstance(primary, Exception):
        latest.add_note(
            f"{label} followed earlier failure: "
            f"{type(primary).__name__}: {primary}"
        )
        for note in getattr(primary, "__notes__", ()):
            latest.add_note(f"earlier failure detail: {note}")
        return latest
    primary.add_note(
        f"{label}: {type(latest).__name__}: {latest}"
    )
    return primary


def _thread_definitely_unstarted(thread: threading.Thread) -> bool:
    """Prove the CPython 3.13 state where no native watcher was created."""

    try:
        started = getattr(thread, "_started", None)
        if (
            not isinstance(started, threading.Event)
            or started.is_set()
            or thread.ident is not None
            or thread.is_alive()
        ):
            return False
        handle = getattr(thread, "_handle", None)
        native_ident = getattr(handle, "ident", None)
    except BaseException:
        return False
    # CPython 3.13 initializes the joinable handle with ident=0. The native
    # start publishes a nonzero handle identity before bootstrap publishes the
    # public Thread.ident/_started receipt.
    return type(native_ident) is int and native_ident == 0


def _identity_from_value(value: object) -> ChallengeIdentity:
    if not isinstance(value, Mapping):
        raise LiveBrokerError("Live broker identity must be an object")
    names = ("contest_id", "category", "challenge_id")
    if not all(isinstance(value.get(name), str) for name in names):
        raise LiveBrokerError("Live broker identity fields must be strings")
    return ChallengeIdentity(
        contest_id=value["contest_id"],
        category=value["category"],
        challenge_id=value["challenge_id"],
    )


def _string(
    params: Mapping[str, object],
    name: str,
    *,
    required: bool = True,
    maximum_bytes: int = 1024 * 1024,
) -> str | None:
    value = params.get(name)
    if value is None and not required:
        return None
    if not isinstance(value, str):
        raise LiveBrokerError(f"{name} must be a string")
    if "\x00" in value or len(value.encode("utf-8")) > maximum_bytes:
        raise LiveBrokerError(f"{name} is invalid or too large")
    return value


def _string_list(
    params: Mapping[str, object],
    name: str,
    *,
    maximum_items: int = 4096,
    maximum_item_bytes: int = 64 * 1024,
    maximum_total_bytes: int = 512 * 1024,
) -> tuple[str, ...]:
    value = params.get(name, [])
    if not isinstance(value, list) or len(value) > maximum_items:
        raise LiveBrokerError(f"{name} must be a bounded string array")
    total_bytes = 0
    for item in value:
        if not isinstance(item, str) or "\x00" in item:
            raise LiveBrokerError(f"{name} must be a bounded string array")
        try:
            item_bytes = len(item.encode("utf-8"))
        except UnicodeError as error:
            raise LiveBrokerError(
                f"{name} must contain valid Unicode strings"
            ) from error
        total_bytes += item_bytes
        if (
            item_bytes > maximum_item_bytes
            or total_bytes > maximum_total_bytes
        ):
            raise LiveBrokerError(f"{name} must be a bounded string array")
    return tuple(value)


def _optional_positive_int(
    params: Mapping[str, object],
    name: str,
    *,
    maximum: int = MAX_LIVE_OPERATION_SECONDS,
) -> int | None:
    value = params.get(name)
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise LiveBrokerError(
            f"{name} must be an integer between 1 and {maximum}"
        )
    return value


def _optional_bounded_int(
    params: Mapping[str, object],
    name: str,
    *,
    minimum: int,
    maximum: int,
) -> int | None:
    if name not in params:
        return None
    value = params[name]
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise LiveBrokerError(
            f"{name} must be an integer between {minimum} and {maximum}"
        )
    return value


def _boolean(params: Mapping[str, object], name: str) -> bool:
    value = params.get(name, False)
    if not isinstance(value, bool):
        raise LiveBrokerError(f"{name} must be a boolean")
    return value


def _optional_probability(
    params: Mapping[str, object],
    name: str,
) -> float | None:
    value = params.get(name)
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0 <= float(value) <= 1
    ):
        raise LiveBrokerError(f"{name} must be a number between 0 and 1")
    return float(value)


def _latest_experiment(state: Any) -> dict[str, object]:
    if not state.experiments:
        raise LiveBrokerError("the broker operation produced no experiment")
    experiment = state.experiments[-1]
    return {
        "experiment_id": experiment.id,
        "status": experiment.status.value,
        "result": experiment.result,
        "artifact_ids": list(experiment.artifact_ids),
    }


def _json_bytes(value: object) -> int:
    return len(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    )


def _bounded_summary_text(value: object, maximum_bytes: int = 4096) -> str:
    encoded = str(value).encode("utf-8", errors="replace")
    if len(encoded) <= maximum_bytes:
        return encoded.decode("utf-8", errors="replace")
    return (
        encoded[:maximum_bytes].decode("utf-8", errors="ignore")
        + "…"
    )


def _bounded_optional_summary_text(value: object) -> str | None:
    return None if value is None else _bounded_summary_text(value)


def _state_summary(
    state: Any,
    *,
    full_state_omitted: bool = False,
) -> dict[str, object]:
    budget = state.budget
    summary: dict[str, object] = {
        "section": "summary",
        "identity": {
            "contest_id": _bounded_summary_text(state.contest_id),
            "category": _bounded_summary_text(state.category),
            "challenge_id": _bounded_summary_text(state.challenge_id),
        },
        "schema_version": state.schema_version,
        "revision": state.revision,
        "status": state.status.value,
        "resume_status": (
            state.resume_status.value
            if state.resume_status is not None
            else None
        ),
        "created_at": _bounded_summary_text(state.created_at),
        "updated_at": _bounded_summary_text(state.updated_at),
        "active_goal_id": _bounded_optional_summary_text(
            state.active_goal_id
        ),
        "budget": {
            "deadline_utc": _bounded_optional_summary_text(
                budget.deadline_utc
            ),
            "allocated_seconds": budget.allocated_seconds,
            "spent_seconds": budget.spent_seconds,
            "remaining_seconds": budget.remaining_seconds,
            "no_progress_since_seconds": (
                budget.no_progress_since_seconds
            ),
            "model_tier": _bounded_optional_summary_text(
                budget.model_tier
            ),
            "curve_profile": _bounded_optional_summary_text(
                budget.curve_profile
            ),
            "refusal_count": len(budget.refusals),
        },
        "counts": {
            section: len(getattr(state, section))
            for section in INSPECT_LIST_SECTIONS
        },
        "source_inventory_count": len(state.source_inventory),
        "prompt_bytes": len(
            state.prompt.encode("utf-8", errors="replace")
        ),
        "description_bytes": len(
            state.description.encode("utf-8", errors="replace")
        ),
        "available_sections": list(INSPECT_SECTIONS),
    }
    if full_state_omitted:
        summary.update(
            {
                "requested_section": "state",
                "full_state_omitted": True,
                "reason": (
                    "full state exceeds the bounded Live response; inspect "
                    "the listed sections with offset/limit"
                ),
            }
        )
    return summary


def _inspect_record(state: Any, section: str, item: Any) -> object:
    if section == "facts":
        return item.to_dict(default_challenge_id=state.challenge_id)
    return item.to_dict()


def _live_visible_artifact(artifact: Any) -> bool:
    """Never expose engine-private proof material to attached model clients."""

    return artifact.extra.get("context_visibility") != "engine_private"


def _inspect_values(state: Any, section: str) -> list[Any] | Any:
    values = getattr(state, section)
    if section == "artifacts":
        return [
            artifact
            for artifact in values
            if _live_visible_artifact(artifact)
        ]
    return values


def _oversized_record_summary(
    record: object,
    *,
    offset: int,
    encoded_bytes: int,
) -> dict[str, object]:
    summary: dict[str, object] = {
        "_truncated": True,
        "_offset": offset,
        "_encoded_bytes": encoded_bytes,
        "_reason": "record exceeds the bounded Live inspect response",
    }
    if not isinstance(record, Mapping):
        return summary
    for name in (
        "id",
        "status",
        "role",
        "kind",
        "type",
        "source",
        "path",
        "locator",
        "created_at",
        "updated_at",
        "statement",
        "description",
        "result",
    ):
        value = record.get(name)
        if isinstance(value, str):
            summary[name] = _bounded_summary_text(value)
        elif value is None or isinstance(value, (bool, int, float)):
            summary[name] = value
    return summary


def _inspect_page(
    state: Any,
    section: str,
    *,
    offset: int,
    limit: int,
) -> dict[str, object]:
    values = _inspect_values(state, section)
    total = len(values)
    index = min(offset, total)
    items: list[object] = []
    truncated_items = 0

    def envelope(next_offset: int | None) -> dict[str, object]:
        return {
            "section": section,
            "revision": state.revision,
            "items": list(items),
            "offset": offset,
            "limit": limit,
            "returned": len(items),
            "total": total,
            "next_offset": next_offset,
            "truncated_items": truncated_items,
        }

    while index < total and len(items) < limit:
        record = _inspect_record(state, section, values[index])
        next_after_record = index + 1
        candidate_next = (
            next_after_record if next_after_record < total else None
        )
        items.append(record)
        if _json_bytes(envelope(candidate_next)) <= MAX_INSPECT_RESULT_BYTES:
            index = next_after_record
            continue
        items.pop()
        if items:
            break
        summary = _oversized_record_summary(
            record,
            offset=index,
            encoded_bytes=_json_bytes(record),
        )
        items.append(summary)
        truncated_items += 1
        if _json_bytes(envelope(candidate_next)) > MAX_INSPECT_RESULT_BYTES:
            raise LiveBrokerError(
                "inspect record summary exceeds the bounded response"
            )
        index = next_after_record

    return envelope(index if index < total else None)


def inspect_state(
    state: Any,
    section: str,
    *,
    offset: int | None = None,
    limit: int | None = None,
) -> object:
    """Return one response-bounded canonical-state view.

    Small unpaginated calls retain the historical raw list/dict shape.
    Large state/list views switch to a summary or pagination envelope before
    reaching either the broker or MCP 1 MiB message limit.
    """

    if section not in INSPECT_SECTIONS:
        raise LiveBrokerError("unsupported inspect section")
    if (
        offset is not None
        and (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or not 0 <= offset <= MAX_INSPECT_OFFSET
        )
    ):
        raise LiveBrokerError(
            f"offset must be an integer between 0 and {MAX_INSPECT_OFFSET}"
        )
    if (
        limit is not None
        and (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_INSPECT_PAGE_ITEMS
        )
    ):
        raise LiveBrokerError(
            "limit must be an integer between 1 and "
            f"{MAX_INSPECT_PAGE_ITEMS}"
        )
    if section in {"summary", "state"}:
        if offset is not None or limit is not None:
            raise LiveBrokerError(
                "offset/limit are supported only for list sections"
            )
        if section == "summary":
            return _state_summary(state)
        full_state = state.to_dict()
        full_state["artifacts"] = [
            artifact.to_dict()
            for artifact in state.artifacts
            if _live_visible_artifact(artifact)
        ]
        if _json_bytes(full_state) <= MAX_INSPECT_RESULT_BYTES:
            return full_state
        return _state_summary(state, full_state_omitted=True)

    values = _inspect_values(state, section)
    pagination_requested = offset is not None or limit is not None
    page_offset = 0 if offset is None else offset
    page_limit = DEFAULT_INSPECT_PAGE_ITEMS if limit is None else limit
    if not pagination_requested and len(values) <= DEFAULT_INSPECT_PAGE_ITEMS:
        records = [
            _inspect_record(state, section, item)
            for item in values
        ]
        if _json_bytes(records) <= MAX_INSPECT_RESULT_BYTES:
            return records
    return _inspect_page(
        state,
        section,
        offset=page_offset,
        limit=page_limit,
    )


class LiveBrokerService:
    """Execute the narrow Live command surface for exactly one challenge."""

    _OPERATIONS = frozenset(
        {
            "agent.flag",
            "agent.fact",
            "agent.goal",
            "agent.hypothesis",
            "agent.experiment",
            "agent.evaluate",
            "agent.artifact",
            "agent.progress",
            "agent.transition",
            "tool.run",
            "tool.start",
            "jobs",
            "inspect",
            "knowledge.search",
            "knowledge.read",
        }
    )
    _BLOCKED_STATE_ALLOWED_OPERATIONS = frozenset(
        {
            "agent.flag",
            "inspect",
            "knowledge.search",
            "knowledge.read",
        }
    )
    _READ_ONLY_OPERATIONS = frozenset(
        {
            "inspect",
            "knowledge.search",
            "knowledge.read",
        }
    )

    @classmethod
    def is_read_only_operation(cls, operation: object) -> bool:
        """Return whether an operation changes no canonical or host state."""

        return (
            isinstance(operation, str)
            and operation in cls._READ_ONLY_OPERATIONS
        )

    @classmethod
    def is_read_only_request(
        cls,
        operation: object,
        params: object,
    ) -> bool:
        if cls.is_read_only_operation(operation):
            return True
        if operation != "jobs" or not isinstance(params, Mapping):
            return False
        action = params.get("action", "list")
        return action in {"list", "status", "log"}

    def __init__(
        self,
        engine: ChallengeEngine,
        identity: ChallengeIdentity,
        authority: CapabilityAuthority,
        expected_token: str,
    ) -> None:
        self.engine = engine
        self.identity = identity
        self.authority = authority
        self.expected_token = expected_token
        try:
            expected_scope = authority.verify(expected_token)
        except CapabilityError as error:
            raise LiveBrokerError("invalid initial Live capability") from error
        actual_scope = engine.sandbox(engine.store.load(identity)).scope_fingerprint
        if expected_scope != actual_scope:
            raise LiveBrokerError(
                "initial Live capability does not match the challenge scope"
            )
        self.expected_scope = expected_scope
        # State transitions and experiment execution are serialized so three
        # logical workers cannot race a state revision. Calls wait here rather
        # than bypassing or narrowing the logical role set.
        self._operation_gate = threading.Lock()

    def _operation_timeout(
        self,
        params: Mapping[str, object],
    ) -> int:
        requested = _optional_positive_int(params, "timeout_seconds")
        if requested is not None:
            return requested
        configured = self.engine.config.runtime.command_timeout_s
        if (
            isinstance(configured, bool)
            or not isinstance(configured, (int, float))
            or not 1 <= configured <= MAX_LIVE_OPERATION_SECONDS
        ):
            raise LiveBrokerError(
                "the configured Live command timeout must be between 1 "
                f"and {MAX_LIVE_OPERATION_SECONDS} seconds"
            )
        return int(configured)

    def _authorize(self, request: object) -> tuple[str, Mapping[str, object]]:
        if not isinstance(request, Mapping) or request.get("schema_version") != 1:
            raise LiveBrokerError("unsupported Live broker request")
        token = request.get("token")
        if (
            not isinstance(token, str)
            or not hmac.compare_digest(token, self.expected_token)
        ):
            raise LiveBrokerError("invalid Live session capability")
        try:
            claimed_scope = self.authority.verify(token)
        except CapabilityError as error:
            raise LiveBrokerError("expired or invalid Live capability") from error
        if claimed_scope != self.expected_scope:
            raise LiveBrokerError("Live capability belongs to another scope")
        identity = _identity_from_value(request.get("identity"))
        if identity != self.identity:
            raise LiveBrokerError("Live request belongs to another challenge")
        operation = request.get("operation")
        params = request.get("params", {})
        if not isinstance(operation, str) or operation not in self._OPERATIONS:
            raise LiveBrokerError("operation is not allowed in a Live session")
        if not isinstance(params, Mapping):
            raise LiveBrokerError("Live broker params must be an object")
        return operation, params

    def dispatch(self, request: object) -> object:
        operation, params = self._authorize(request)
        # Canonical state is atomically replaced, and knowledge readers use a
        # shared file lock. These operations need no long-operation writer
        # lane and must remain available while a tool or state mutation runs.
        if self.is_read_only_request(operation, params):
            return self._dispatch_authorized(operation, params)
        # A plausible flag must remain durable and visible even while a bounded
        # tool command is still running. StateStore serializes the short state
        # commit itself; the long-operation gate is intentionally not held.
        if operation == "agent.flag":
            return self._dispatch_authorized(operation, params)
        with self._operation_gate:
            if operation not in self._BLOCKED_STATE_ALLOWED_OPERATIONS:
                self.engine._require_live_mutation_allowed(
                    self.engine.store.load(self.identity)
                )
            return self._dispatch_authorized(operation, params)

    def _dispatch_authorized(
        self,
        operation: str,
        params: Mapping[str, object],
    ) -> object:
        identity = self.identity
        if operation == "agent.flag":
            value = _string(params, "value", maximum_bytes=4096)
            source = _string(params, "source", maximum_bytes=4096)
            source_run_id = _string(
                params,
                "source_run_id",
                required=False,
                maximum_bytes=4096,
            )
            state = self.engine.record_candidate(
                identity,
                value,
                source=source,
                source_run_id=source_run_id,
            )
            candidate = next(
                item for item in state.candidates if item.value == value
            )
            return {"candidate_id": candidate.id}

        if operation == "agent.fact":
            statement = _string(params, "statement")
            provenance = Provenance(_string(params, "provenance", maximum_bytes=64))
            if provenance is not Provenance.MODEL_CLAIMED:
                raise LiveBrokerError(
                    "Live facts may only use model_claimed provenance"
                )
            state = self.engine.record_fact(
                identity,
                statement,
                provenance=provenance,
                source_run_id=_string(
                    params, "source_run_id", required=False, maximum_bytes=4096
                ),
                artifact_id=_string(
                    params, "artifact_id", required=False, maximum_bytes=4096
                ),
                locator=_string(
                    params, "locator", required=False, maximum_bytes=4096
                ),
                _live_only=True,
            )
            return {"fact_id": state.facts[-1].id}

        if operation == "agent.goal":
            state, goal_id = self.engine.manage_goal(
                identity,
                action=_string(params, "action", maximum_bytes=64),
                goal_id=_string(
                    params,
                    "goal_id",
                    required=False,
                    maximum_bytes=4096,
                ),
                description=_string(
                    params,
                    "description",
                    required=False,
                ),
                depends_on=_string_list(params, "depends_on"),
                artifact_ids=_string_list(params, "artifact_ids"),
                blocked_reason=_string(
                    params,
                    "blocked_reason",
                    required=False,
                ),
                activate=_boolean(params, "activate"),
                _live_only=True,
            )
            goal = next(item for item in state.goals if item.id == goal_id)
            return {
                "goal_id": goal_id,
                "status": goal.status.value,
                "active_goal_id": state.active_goal_id,
            }

        if operation == "agent.hypothesis":
            status_value = _string(
                params,
                "status",
                maximum_bytes=64,
            )
            if status_value not in LIVE_HYPOTHESIS_STATUSES:
                raise LiveBrokerError(
                    "Live hypothesis updates may only retain open status; "
                    "use agent.evaluate for evidence-backed outcomes"
                )
            state, hypothesis_id = self.engine.manage_hypothesis(
                identity,
                action=_string(params, "action", maximum_bytes=64),
                hypothesis_id=_string(
                    params,
                    "hypothesis_id",
                    required=False,
                    maximum_bytes=4096,
                ),
                statement=_string(
                    params,
                    "statement",
                    required=False,
                ),
                falsifier=_string(
                    params,
                    "falsifier",
                    required=False,
                ),
                status=HypothesisStatus(status_value),
                evidence_fact_ids=_string_list(
                    params,
                    "evidence_fact_ids",
                ),
                evidence_artifact_ids=_string_list(
                    params,
                    "evidence_artifact_ids",
                ),
                evidence_run_ids=_string_list(
                    params,
                    "evidence_run_ids",
                ),
                confidence=_optional_probability(params, "confidence"),
                refuted_by=_string(
                    params,
                    "refuted_by",
                    required=False,
                ),
                open_only=True,
                _live_only=True,
            )
            hypothesis = next(
                item for item in state.hypotheses
                if item.id == hypothesis_id
            )
            return {
                "hypothesis_id": hypothesis_id,
                "status": hypothesis.status.value,
            }

        if operation == "agent.experiment":
            command = _string_list(params, "command")
            state, experiment_id = self.engine.register_experiment(
                identity,
                command=command,
                expected_observation=_string(params, "expected_observation"),
                keep_if=_string(params, "keep_if"),
                drop_if=_string(params, "drop_if"),
                hypothesis_ids=_string_list(params, "hypothesis_ids"),
                timeout_seconds=self._operation_timeout(params),
                resource_class=_string(
                    params, "resource_class", maximum_bytes=64
                ),
                network_target=_string(
                    params, "network_target", required=False, maximum_bytes=4096
                ),
                needs_kvm=_boolean(params, "needs_kvm"),
                _live_only=True,
            )
            del state
            return {"experiment_id": experiment_id}

        if operation == "agent.evaluate":
            experiment_id = _string(
                params,
                "experiment_id",
                maximum_bytes=4096,
            )
            state = self.engine.evaluate_experiment(
                identity,
                experiment_id,
                status=ExperimentStatus(
                    _string(params, "status", maximum_bytes=64)
                ),
                reason=_string(params, "reason"),
                evidence_fact_ids=_string_list(
                    params,
                    "evidence_fact_ids",
                ),
                evidence_artifact_ids=_string_list(
                    params,
                    "evidence_artifact_ids",
                ),
                evidence_run_ids=_string_list(
                    params,
                    "evidence_run_ids",
                ),
                support_hypothesis_ids=_string_list(
                    params,
                    "support_hypothesis_ids",
                ),
                refute_hypothesis_ids=_string_list(
                    params,
                    "refute_hypothesis_ids",
                ),
                _live_only=True,
            )
            experiment = next(
                item for item in state.experiments
                if item.id == experiment_id
            )
            return {
                "experiment_id": experiment_id,
                "status": experiment.status.value,
            }

        if operation == "agent.artifact":
            unexpected = set(params).difference({"locator"})
            if unexpected:
                raise LiveBrokerError(
                    f"unexpected agent.artifact params: {sorted(unexpected)}"
                )
            state, artifact = self.engine.register_workspace_artifact(
                identity,
                _string(params, "locator", maximum_bytes=4096),
                source_run_id=None,
                _live_only=True,
            )
            del state
            return {
                "artifact_id": artifact.id,
                "sha256": artifact.sha256,
            }

        if operation == "agent.progress":
            state = self.engine.mark_progress(
                identity,
                _string(params, "statement"),
                run_id=_string(
                    params, "run_id", required=False, maximum_bytes=4096
                ),
                artifact_ids=_string_list(params, "artifact_ids"),
                _live_only=True,
            )
            return {"progress_id": state.progress_markers[-1].id}

        if operation == "agent.transition":
            target = ChallengeStatus(
                _string(params, "target", maximum_bytes=64)
            )
            if target.value not in LIVE_TRANSITION_TARGETS:
                if target is ChallengeStatus.ABANDONED:
                    raise LiveBrokerError(
                        "ABANDONED is reserved for an operator-owned path"
                    )
                raise LiveBrokerError(
                    f"{target.value} is not an allowed Live transition target"
                )
            state = self.engine.transition(
                identity,
                target,
                _live_only=True,
            )
            return {"status": state.status.value}

        if operation == "tool.run":
            state = self.engine.run_tool_command(
                identity,
                _string_list(params, "command"),
                expected_observation=_string(params, "expected_observation"),
                keep_if=_string(params, "keep_if"),
                drop_if=_string(params, "drop_if"),
                hypothesis_ids=_string_list(params, "hypothesis_ids"),
                timeout_seconds=self._operation_timeout(params),
                resource_class=_string(
                    params, "resource_class", maximum_bytes=64
                ),
                network_target=_string(
                    params, "network_target", required=False, maximum_bytes=4096
                ),
                needs_kvm=_boolean(params, "needs_kvm"),
                _session_owned=True,
                _live_only=True,
            )
            return _latest_experiment(state)

        if operation == "tool.start":
            state, ref = self.engine.start_background_job(
                identity,
                _string_list(params, "command"),
                name=_string(
                    params,
                    "name",
                    required=False,
                    maximum_bytes=1024,
                ),
                timeout_seconds=self._operation_timeout(params),
                resource_class=_string(
                    params,
                    "resource_class",
                    maximum_bytes=64,
                ),
                network_target=_string(
                    params,
                    "network_target",
                    required=False,
                    maximum_bytes=4096,
                ),
                needs_kvm=_boolean(params, "needs_kvm"),
                _session_owned=True,
                _live_only=True,
            )
            return {
                "schema_version": 1,
                "kind": "background_job_launch",
                "state_revision": state.revision,
                "ref": {
                    "job_id": ref.job_id,
                    "scope_fingerprint": ref.scope_fingerprint,
                    "runtime_id": ref.runtime_id,
                    "supervisor_id": ref.supervisor_id,
                },
            }

        if operation == "jobs":
            action = _string(
                params,
                "action",
                required=False,
                maximum_bytes=32,
            ) or "list"
            if action not in {
                "list",
                "recover",
                "status",
                "log",
                "cancel",
            }:
                raise LiveBrokerError("invalid jobs action")
            if action in {"list", "recover"}:
                unexpected = set(params).difference(
                    {
                        "action",
                        "runtime_id",
                        "tail_bytes",
                        "grace_seconds",
                    }
                )
                if unexpected:
                    raise LiveBrokerError(
                        f"unexpected jobs params: {sorted(unexpected)}"
                    )
                state, statuses = self.engine.list_background_jobs(
                    identity,
                    recover=action == "recover",
                    _live_only=True,
                )
                return {
                    "schema_version": 1,
                    "kind": "supervised_job_list",
                    "experiment_id": None,
                    "state_revision": state.revision,
                    "count": len(statuses),
                    "jobs": [
                        {
                            "ref": {
                                "job_id": status.ref.job_id,
                                "scope_fingerprint": (
                                    status.ref.scope_fingerprint
                                ),
                                "runtime_id": status.ref.runtime_id,
                                "supervisor_id": (
                                    status.ref.supervisor_id
                                ),
                            },
                            "status": status.status.value,
                            "exit_code": status.exit_code,
                            "timed_out": status.timed_out,
                            "cancelled": status.cancelled,
                            "started_at": status.started_at,
                            "finished_at": status.finished_at,
                        }
                        for status in statuses
                    ],
                }
            state = self.engine.store.read_snapshot(identity)
            sandbox = self.engine.sandbox(state)
            ref = JobRef(
                job_id=_string(
                    params,
                    "job_id",
                    maximum_bytes=32,
                ),
                scope_fingerprint=sandbox.scope_fingerprint,
                runtime_id=_string(
                    params,
                    "runtime_id",
                    maximum_bytes=128,
                ),
                supervisor_id=_string(
                    params,
                    "supervisor_id",
                    maximum_bytes=64,
                ),
            )
            if action == "log":
                tail_bytes = _optional_bounded_int(
                    params,
                    "tail_bytes",
                    minimum=0,
                    maximum=1024 * 1024,
                )
                log = self.engine.background_job_log(
                    identity,
                    ref,
                    tail_bytes=8192 if tail_bytes is None else tail_bytes,
                )
                return {
                    "schema_version": 1,
                    "kind": "supervised_job_log",
                    "ref": {
                        "job_id": ref.job_id,
                        "scope_fingerprint": ref.scope_fingerprint,
                        "runtime_id": ref.runtime_id,
                        "supervisor_id": ref.supervisor_id,
                    },
                    "stdout": log.stdout,
                    "stderr": log.stderr,
                    "stdout_bytes": log.stdout_bytes,
                    "stderr_bytes": log.stderr_bytes,
                    "stdout_truncated": log.stdout_truncated,
                    "stderr_truncated": log.stderr_truncated,
                }
            if action == "cancel":
                grace = _optional_bounded_int(
                    params,
                    "grace_seconds",
                    minimum=0,
                    maximum=30,
                )
                current, status = self.engine.cancel_background_job(
                    identity,
                    ref,
                    grace_seconds=3 if grace is None else grace,
                    _live_only=True,
                )
            else:
                current, status = self.engine.background_job_status(
                    identity,
                    ref,
                    _live_only=True,
                )
            return {
                "schema_version": 1,
                "kind": "supervised_job_status",
                "state_revision": current.revision,
                "ref": {
                    "job_id": ref.job_id,
                    "scope_fingerprint": ref.scope_fingerprint,
                    "runtime_id": ref.runtime_id,
                    "supervisor_id": ref.supervisor_id,
                },
                "status": status.status.value,
                "exit_code": status.exit_code,
                "timed_out": status.timed_out,
                "cancelled": status.cancelled,
                "started_at": status.started_at,
                "finished_at": status.finished_at,
            }

        if operation == "inspect":
            section = _string(params, "section", maximum_bytes=64)
            unexpected = set(params).difference(
                {"section", "offset", "limit"}
            )
            if unexpected:
                raise LiveBrokerError(
                    f"unexpected inspect params: {sorted(unexpected)}"
                )
            offset = _optional_bounded_int(
                params,
                "offset",
                minimum=0,
                maximum=MAX_INSPECT_OFFSET,
            )
            limit = _optional_bounded_int(
                params,
                "limit",
                minimum=1,
                maximum=MAX_INSPECT_PAGE_ITEMS,
            )
            return inspect_state(
                self.engine.store.read_snapshot(identity),
                section,
                offset=offset,
                limit=limit,
            )

        if operation == "knowledge.search":
            unexpected = set(params).difference({"query", "limit"})
            if unexpected:
                raise LiveBrokerError(
                    f"unexpected knowledge.search params: {sorted(unexpected)}"
                )
            limit = _optional_bounded_int(
                params,
                "limit",
                minimum=1,
                maximum=MAX_KNOWLEDGE_SEARCH_RESULTS,
            )
            return KnowledgeStore(self.engine.store).search_envelope(
                identity,
                _string(params, "query", maximum_bytes=4096),
                limit=10 if limit is None else limit,
            )

        if operation == "knowledge.read":
            unexpected = set(params).difference(
                {"document_id", "offset_bytes", "max_bytes"}
            )
            if unexpected:
                raise LiveBrokerError(
                    f"unexpected knowledge.read params: {sorted(unexpected)}"
                )
            offset_bytes = _optional_bounded_int(
                params,
                "offset_bytes",
                minimum=0,
                maximum=MAX_EXTRACTED_TEXT_BYTES,
            )
            max_bytes = _optional_bounded_int(
                params,
                "max_bytes",
                minimum=1,
                maximum=MAX_KNOWLEDGE_READ_BYTES,
            )
            return KnowledgeStore(self.engine.store).read(
                identity,
                _string(params, "document_id", maximum_bytes=64),
                offset_bytes=0 if offset_bytes is None else offset_bytes,
                max_bytes=(
                    DEFAULT_KNOWLEDGE_READ_BYTES
                    if max_bytes is None
                    else max_bytes
                ),
            ).to_dict()

        raise AssertionError(f"unhandled Live broker operation: {operation}")


def _encode_message(value: object) -> bytes:
    payload = (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if len(payload) > MAX_LIVE_RPC_BYTES:
        raise LiveBrokerError("Live broker response exceeds 1 MiB")
    return payload


def _strict_json_loads(data: bytes) -> object:
    def unique_object(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        value: dict[str, object] = {}
        for name, item in pairs:
            if name in value:
                raise LiveBrokerError(
                    f"duplicate JSON object key: {name}"
                )
            value[name] = item
        return value

    def reject_constant(value: str) -> object:
        raise LiveBrokerError(f"non-finite JSON number is not allowed: {value}")

    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )


def _open_private_directory(
    path: Path,
    *,
    pending_handoff: list[int] | None = None,
) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None

    def close_descriptor() -> BaseException | None:
        nonlocal descriptor
        closing = descriptor
        if closing is None:
            return None
        descriptor = None
        if (
            pending_handoff is not None
            and pending_handoff
            and pending_handoff[-1] == closing
        ):
            pending_handoff.pop()
        try:
            # Inode equality cannot distinguish a same-directory descriptor
            # concurrently reused at this integer.  Consume ownership before
            # one close attempt and never inspect or retry it afterward.
            os.close(closing)
        except BaseException as error:
            return error
        return None

    try:
        descriptor = os.open(path, flags)
        if pending_handoff is not None:
            pending_handoff.append(descriptor)
        metadata = os.fstat(descriptor)
    except BaseException as error:
        if descriptor is not None:
            cleanup_error = close_descriptor()
            if cleanup_error is not None:
                error.add_note(
                    "Live broker mailbox descriptor cleanup failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
        if not isinstance(error, OSError):
            raise
        raise LiveBrokerError(
            f"Live broker mailbox is unavailable: {error}"
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        close_error = close_descriptor()
        if close_error is not None:
            raise close_error
        raise LiveBrokerError(
            "Live broker mailbox must be a private directory owned by this user"
        )
    return descriptor


class _LiveBrokerDirectoryFd:
    """Resource-free owner for one client/server mailbox directory fd."""

    def __init__(self) -> None:
        self._descriptor: int | None = None

    def open(self, path: Path) -> int:
        if self._descriptor is not None:
            raise RuntimeError("Live broker directory fd owner is already armed")
        pending_handoff: list[int] = []
        try:
            descriptor = _open_private_directory(
                path,
                pending_handoff=pending_handoff,
            )
            self._descriptor = descriptor
            pending_handoff.clear()
            return descriptor
        except BaseException:
            if self._descriptor is None and pending_handoff:
                self._descriptor = pending_handoff[0]
            pending_handoff.clear()
            raise

    def close(self) -> BaseException | None:
        descriptor = self._descriptor
        if descriptor is None:
            return None
        # Consume ownership before the one close attempt. A close return
        # interruption must never re-close a same-inode peer that reused this
        # numeric fd.
        self._descriptor = None
        try:
            os.close(descriptor)
        except BaseException as error:
            return error
        return None

    def __del__(self) -> None:
        try:
            self.close()
        except BaseException:
            pass


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short mailbox write")
        view = view[written:]


def _atomic_mailbox_write(
    directory_fd: int,
    final_name: str,
    payload: bytes,
) -> None:
    # Keep transport draft names independent from request IDs. Besides making
    # deterministic replay tests accurate, this prevents a retried request ID
    # from sharing a draft namespace with the broker response writer.
    temporary_name = f".mailbox-{secrets.token_hex(16)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None

    def close_descriptor() -> BaseException | None:
        nonlocal descriptor
        closing = descriptor
        if closing is None:
            return None
        descriptor = None
        try:
            os.close(closing)
        except BaseException as error:
            return error
        return None

    try:
        descriptor = os.open(
            temporary_name,
            flags,
            0o600,
            dir_fd=directory_fd,
        )
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        close_error = close_descriptor()
        if close_error is not None:
            raise close_error
        # Replacing a hostile symlink or hard-link directory entry never
        # follows it; the response/request content stays inside the mailbox.
        os.replace(
            temporary_name,
            final_name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    finally:
        active_error = sys.exception()
        if descriptor is not None:
            cleanup_error = close_descriptor()
            if cleanup_error is not None:
                if active_error is None:
                    raise cleanup_error
                active_error.add_note(
                    "mailbox descriptor cleanup failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def _read_mailbox_file(directory_fd: int, name: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as error:
        raise LiveBrokerError(f"invalid Live mailbox entry: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or opened.st_mode & 0o077
            or (opened.st_dev, opened.st_ino)
            != (before.st_dev, before.st_ino)
            or opened.st_size != before.st_size
            or opened.st_mtime_ns != before.st_mtime_ns
            or opened.st_size > MAX_LIVE_RPC_BYTES
        ):
            raise LiveBrokerError("Live mailbox entry is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = MAX_LIVE_RPC_BYTES + 1
        while remaining:
            block = os.read(descriptor, min(64 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        after = os.fstat(descriptor)
        data = b"".join(chunks)
        if (
            after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or len(data) != opened.st_size
            or len(data) > MAX_LIVE_RPC_BYTES
        ):
            raise LiveBrokerError("Live mailbox entry changed while being read")
        return data
    finally:
        os.close(descriptor)


class _ReadLanePermit:
    """Finalizer-safe ownership of one admitted read-only operation."""

    def __init__(self, server: LiveBrokerServer) -> None:
        self._server = server
        self._active = False

    def activate(self) -> None:
        if self._active:
            raise RuntimeError("Live broker read permit is already active")
        self._active = True

    def release(self) -> None:
        if not self._active:
            return
        # Consume local ownership first. The server-side decrement is one
        # exact lock transaction and must never be attempted twice.
        self._active = False
        self._server._release_read_lane()

    def __del__(self) -> None:
        try:
            self.release()
        except BaseException:
            pass


class _BackgroundRequestDispatch:
    """Arbitrate one claimed request between submitter and worker.

    ``ThreadPoolExecutor.submit`` may have enqueued and even started its
    callable when an interrupt is observed at the call's return boundary.
    This small state machine lets exactly one side retain ownership of the
    claimed mailbox entry in that ambiguous case.
    """

    def __init__(
        self,
        server: LiveBrokerServer,
        processing: str,
        request_id: str,
        request: object,
        *,
        release_lane: Callable[[], None] | None = None,
    ) -> None:
        self._server = server
        self._processing = processing
        self._request_id = request_id
        self._request = request
        self._release_lane = (
            release_lane
            if release_lane is not None
            else server._operation_idle.set
        )
        self._state_lock = threading.Lock()
        self._state = "pending"

    def cancel_before_worker_start(self) -> bool:
        """Return whether the submitter durably reclaimed the request.

        The result is intentionally idempotent. A control exception can be
        observed after the state changes to ``cancelled`` but before this call
        returns; the submitter's outer guard must be able to read the same
        receipt again instead of misclassifying it as worker ownership.
        """

        with self._state_lock:
            if self._state == "pending":
                self._state = "cancelled"
            return self._state == "cancelled"

    def _claim_worker(self) -> bool:
        """Publish worker ownership only after its lock guard can unwind."""

        with self._state_lock:
            if self._state != "pending":
                return False
            self._state = "worker"
            return True

    def __call__(self) -> None:
        try:
            try:
                # Install the lane finalizer before changing the durable
                # ownership state. Keep the lock transaction in a helper frame
                # so a control exception observed by this frame after the
                # worker receipt cannot strand the non-reentrant state lock.
                if not self._claim_worker():
                    return
                self._server._dispatch_claimed(
                    self._processing,
                    self._request_id,
                    self._request,
                    background=False,
                )
            except BaseException as error:
                # A worker BaseException would otherwise live only in an
                # unobserved Future while the client waits for a response.
                try:
                    self._server._remove_claimed_request(self._processing)
                except BaseException as cleanup_error:
                    error.add_note(
                        "Live broker background request cleanup failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
                self._server._set_terminal_error(
                    LiveBrokerError(
                        "Live broker background operation was interrupted: "
                        f"{type(error).__name__}: "
                        f"{str(error)[:4096] or 'no detail'}"
                    )
                )
                raise
        finally:
            release_lane = False
            with self._state_lock:
                if self._state in {"pending", "worker"}:
                    # Publish the terminal worker receipt before releasing the
                    # lane. A cancelled or already-finished late callback owns
                    # no lane and must not set an event that a newer request
                    # has since cleared.
                    self._state = "finished"
                    release_lane = True
            if release_lane:
                self._release_lane()


class LiveBrokerServer:
    """Poll a private, bounded filesystem mailbox for one Live session.

    Codex 0.145 does not make a parent-owned Unix socket reachable from its
    workspace sandbox even when the experimental network proxy allowlist is
    configured. The mailbox keeps command networking disabled while retaining
    the same capability-, scope-, identity-, and operation-checked broker.
    """

    def __init__(self, directory: Path, service: LiveBrokerService) -> None:
        self.directory = directory
        self.service = service
        self._directory_fd: int | None = None
        self._stop = threading.Event()
        self._session_id = uuid.uuid4().hex
        self._accepted_request_ids: set[str] = set()
        self._terminal_error: LiveBrokerError | None = None
        self._terminal_lock = threading.Lock()
        # Mutations stay ordered on one bounded lane. Read-only snapshots have
        # separate bounded admission and may overlap that writer and each
        # other. This does not change the three logical model roles or create
        # a scheduler/priority queue. The watcher also remains free to commit
        # agent.flag requests while a long mutation is occupied.
        self._operation_idle = threading.Event()
        self._operation_idle.set()
        self._read_state_lock = threading.Lock()
        self._active_reads = 0
        self._reads_idle = threading.Event()
        self._reads_idle.set()
        self._deferred_operation_names: set[str] = set()
        self._operation_executor: ThreadPoolExecutor | None = None
        self._thread: threading.Thread | None = None

    def _reserve_read_lane(self) -> _ReadLanePermit | None:
        """Reserve one bounded reader without waiting for the writer lane."""

        permit = _ReadLanePermit(self)
        with self._read_state_lock:
            if self._active_reads >= MAX_CONCURRENT_READ_ONLY_OPERATIONS:
                return None
            # Arm the caller/finalizer cleanup before publishing the count.
            # An interruption between these lines may attempt a harmless
            # underflow release, but cannot strand a published reservation.
            permit.activate()
            self._active_reads += 1
            self._reads_idle.clear()
            return permit

    def _release_read_lane(self) -> None:
        with self._read_state_lock:
            if self._active_reads <= 0:
                raise RuntimeError("Live broker read lane is not reserved")
            self._active_reads -= 1
            if self._active_reads == 0:
                self._reads_idle.set()

    @staticmethod
    def _retry_lifecycle_step(
        label: str,
        operation: Callable[[], None],
    ) -> tuple[BaseException | None, bool]:
        """Run one exact lifecycle step with one bounded retry."""

        first_error: BaseException | None = None
        for attempt in range(2):
            try:
                operation()
            except BaseException as error:
                if first_error is None:
                    first_error = error
                elif (
                    not isinstance(error, Exception)
                    and isinstance(first_error, Exception)
                ):
                    error.add_note(
                        f"{label} superseded an earlier "
                        f"{type(first_error).__name__}: {first_error}"
                    )
                    first_error = error
                else:
                    first_error.add_note(
                        f"{label} retry failed: "
                        f"{type(error).__name__}: {error}"
                    )
                if attempt == 0:
                    continue
            else:
                if first_error is not None and not isinstance(
                    first_error, Exception
                ):
                    return first_error, True
                return None, True
        return first_error, False

    def _drain_operation_lane(self) -> BaseException | None:
        """Wait for an admitted operation independently of executor internals.

        CPython can start a ThreadPoolExecutor worker before publishing it in
        the executor's thread registry.  A control interruption in that
        handoff can therefore make ``shutdown(wait=True)`` return while the
        callback is still active.  The lane event is owned by the dispatch
        itself, so it remains authoritative across that registry gap.
        """

        primary_error: BaseException | None = None
        failures = 0
        while not self._operation_idle.is_set():
            try:
                self._operation_idle.wait()
            except BaseException as error:
                failures += 1
                if primary_error is None:
                    primary_error = error
                elif (
                    not isinstance(error, Exception)
                    and isinstance(primary_error, Exception)
                ):
                    error.add_note(
                        "Live broker operation drain superseded an earlier "
                        f"{type(primary_error).__name__}: {primary_error}"
                    )
                    primary_error = error
                else:
                    primary_error.add_note(
                        "Live broker operation drain retry failed: "
                        f"{type(error).__name__}: {error}"
                    )
        if primary_error is not None:
            primary_error.add_note(
                "Live broker operation drain completed after "
                f"{failures} interruption"
                + ("" if failures == 1 else "s")
            )
        return primary_error

    def _drain_read_lanes(self) -> BaseException | None:
        """Wait until every admitted read-only snapshot has returned."""

        primary_error: BaseException | None = None
        failures = 0
        while not self._reads_idle.is_set():
            try:
                self._reads_idle.wait()
            except BaseException as error:
                failures += 1
                if primary_error is None:
                    primary_error = error
                else:
                    primary_error = _prefer_control_error(
                        primary_error,
                        error,
                        label=(
                            "Live broker read-only operation drain "
                            "was interrupted"
                        ),
                    )
        if primary_error is not None:
            primary_error.add_note(
                "Live broker read-only drain completed after "
                f"{failures} interruption"
                + ("" if failures == 1 else "s")
            )
        return primary_error

    @staticmethod
    def _drain_watcher(
        thread: threading.Thread,
    ) -> tuple[BaseException | None, bool]:
        """Wait through the native-start/bootstrap gap, then join exactly once."""

        try:
            started = getattr(thread, "_started", None)
        except BaseException as error:
            return error, False
        if not isinstance(started, threading.Event):
            return (
                LiveBrokerError(
                    "Live broker watcher has no verifiable startup receipt"
                ),
                False,
            )

        primary_error: BaseException | None = None

        def record_error(label: str, error: BaseException) -> None:
            nonlocal primary_error
            if primary_error is None:
                primary_error = error
            else:
                primary_error = _prefer_control_error(
                    primary_error,
                    error,
                    label=label,
                )

        # Thread.start() can be interrupted after _start_joinable_thread()
        # publishes a nonzero private handle identity but before bootstrap sets
        # Thread.ident/_started. The native watcher still exists in that state.
        while not started.is_set():
            try:
                started.wait()
            except BaseException as error:
                record_error(
                    "Live broker watcher bootstrap wait was interrupted",
                    error,
                )

        while True:
            try:
                thread.join()
            except BaseException as error:
                record_error(
                    "Live broker watcher join was interrupted",
                    error,
                )
                continue
            try:
                if not thread.is_alive():
                    break
            except BaseException as error:
                record_error(
                    "Live broker watcher state check was interrupted",
                    error,
                )
        return primary_error, True

    def _close_directory_fd(self) -> BaseException | None:
        """Attempt one close after publishing the mailbox fd as unowned."""

        descriptor = self._directory_fd
        if descriptor is None:
            return None
        self._directory_fd = None
        try:
            os.close(descriptor)
        except BaseException as error:
            return error
        return None

    def _cleanup_lifecycle(
        self,
        *,
        write_closing_status: bool,
    ) -> list[tuple[str, BaseException]]:
        """Stop every owned activity before releasing the parent session."""

        errors: list[tuple[str, BaseException]] = []
        self._stop.set()
        thread = self._thread
        watcher_drained = True
        if thread is not None and _thread_definitely_unstarted(thread):
            self._thread = None
        elif thread is not None:
            join_error, join_completed = self._drain_watcher(thread)
            if join_error is not None:
                errors.append(("watcher join", join_error))
            if join_completed:
                self._thread = None
            else:
                watcher_drained = False
        if not watcher_drained:
            # The mailbox and operation executor remain owned until the exact
            # watcher can be proved unstarted or joined.
            return errors
        executor = self._operation_executor
        if executor is not None:
            shutdown_error, shutdown_completed = (
                self._retry_lifecycle_step(
                    "Live broker operation executor shutdown",
                    lambda: executor.shutdown(
                        wait=True,
                        # Every accepted request owns a claimed mailbox entry
                        # and the lane event. Let queued dispatches run their
                        # exact finalizer instead of cancelling the Future
                        # before it can publish lane-idle.
                        cancel_futures=False,
                    ),
                )
            )
            if shutdown_error is not None:
                errors.append(
                    ("operation executor shutdown", shutdown_error)
                )
            if shutdown_completed:
                self._operation_executor = None
        drain_error = self._drain_operation_lane()
        if drain_error is not None:
            errors.append(("operation drain", drain_error))
        read_drain_error = self._drain_read_lanes()
        if read_drain_error is not None:
            errors.append(("read-only operation drain", read_drain_error))
        if (
            write_closing_status
            and self._directory_fd is not None
            and self._terminal_error is None
        ):
            try:
                self._write_status("closing")
            except (LiveBrokerError, RuntimeError, ValueError, OSError):
                pass
            except BaseException as error:
                errors.append(("closing status write", error))
        close_error = self._close_directory_fd()
        if close_error is not None:
            errors.append(("directory fd close", close_error))
        return errors

    def _request_names(self) -> tuple[str, ...]:
        names: list[str] = []
        try:
            with os.scandir(self._directory_fd) as entries:
                for index, entry in enumerate(entries, start=1):
                    if index > MAX_MAILBOX_SCAN_ENTRIES:
                        raise LiveBrokerError(
                            "Live mailbox entry limit exceeded"
                        )
                    if _REQUEST_NAME.fullmatch(entry.name):
                        names.append(entry.name)
        except OSError as error:
            raise LiveBrokerError(
                f"Live mailbox scan failed: {error}"
            ) from error
        return tuple(sorted(names))

    def _write_status(
        self,
        state: str,
        *,
        error: str | None = None,
    ) -> None:
        value: dict[str, object] = {
            "schema_version": 1,
            "session_id": self._session_id,
            "state": state,
        }
        if error is not None:
            value["error"] = error[:4096]
        _atomic_mailbox_write(
            self._directory_fd,
            _SERVER_STATUS_NAME,
            _encode_message(value),
        )

    def _reserve_request_id(self, request_id: str) -> None:
        if request_id in self._accepted_request_ids:
            raise LiveBrokerError(
                "Live mailbox request id was already accepted"
            )
        if len(self._accepted_request_ids) >= MAX_LIVE_SESSION_REQUESTS:
            raise LiveBrokerError(
                "Live session request limit exceeded; start a new session"
            )
        # Reserve before dispatch. IDs are never evicted during this session,
        # including when authorization or the requested operation later fails.
        self._accepted_request_ids.add(request_id)

    def _write_response(
        self,
        request_id: str,
        response: object,
    ) -> None:
        try:
            encoded = _encode_message(response)
        except LiveBrokerError:
            encoded = _encode_message(
                {
                    "schema_version": 1,
                    "request_id": request_id,
                    "ok": False,
                    "error": "Live broker response exceeds 1 MiB",
                }
            )
        _atomic_mailbox_write(
            self._directory_fd,
            f"response-{request_id}.json",
            encoded,
        )

    def _write_request_failure(
        self,
        request_id: str,
        error: BaseException,
    ) -> None:
        _atomic_mailbox_write(
            self._directory_fd,
            f"error-{request_id}.json",
            _encode_message(
                {
                    "schema_version": 1,
                    "request_id": request_id,
                    "ok": False,
                    "error": (
                        str(error)[:4096]
                        or "Live broker could not publish the response"
                    ),
                }
            ),
        )

    def _set_terminal_error(self, error: BaseException) -> None:
        with self._terminal_lock:
            if self._terminal_error is None:
                self._terminal_error = LiveBrokerError(str(error))
            terminal = self._terminal_error
        try:
            self._write_status("error", error=str(terminal))
        except Exception:
            pass
        self._stop.set()

    def _remove_claimed_request(self, processing: str) -> None:
        try:
            os.unlink(processing, dir_fd=self._directory_fd)
        except FileNotFoundError:
            return
        os.fsync(self._directory_fd)

    def _dispatch_claimed(
        self,
        processing: str,
        request_id: str,
        request: object,
        *,
        background: bool,
    ) -> None:
        cleanup_error: OSError | None = None
        try:
            try:
                response: object = {
                    "schema_version": 1,
                    "request_id": request_id,
                    "ok": True,
                    "result": self.service.dispatch(request),
                }
            except (
                UnicodeError,
                json.JSONDecodeError,
                LiveBrokerError,
                RuntimeError,
                ValueError,
                OSError,
            ) as error:
                response = {
                    "schema_version": 1,
                    "request_id": request_id,
                    "ok": False,
                    "error": (
                        str(error)[:4096]
                        or "Live broker operation failed"
                    ),
                }
            finally:
                try:
                    self._remove_claimed_request(processing)
                except OSError as error:
                    cleanup_error = error
            try:
                self._write_response(request_id, response)
            except Exception as error:
                try:
                    self._write_request_failure(request_id, error)
                except Exception as signal_error:
                    self._set_terminal_error(
                        LiveBrokerError(
                            "Live broker could not publish a request failure: "
                            f"{signal_error}"
                        )
                    )
            if cleanup_error is not None:
                self._set_terminal_error(
                    LiveBrokerError(
                        "Live broker could not remove a claimed request: "
                        f"{cleanup_error}"
                    )
                )
        finally:
            # Never leave the bounded operation lane permanently occupied
            # because dispatch or transport cleanup failed.
            if background:
                self._operation_idle.set()

    def _process(self, name: str) -> None:
        match = _REQUEST_NAME.fullmatch(name)
        if match is None:
            return
        request_id = match.group(1)
        processing = f".processing-{request_id}-{uuid.uuid4().hex}.json"
        handed_off = False
        cleanup_attempted = False
        claim_may_exist = False
        release_reserved_lane: Callable[[], None] | None = None
        dispatch: _BackgroundRequestDispatch | None = None
        try:
            # Set cleanup intent before rename. An interrupt can be delivered
            # after the directory entry moved but before the call returns.
            claim_may_exist = True
            try:
                os.rename(
                    name,
                    processing,
                    src_dir_fd=self._directory_fd,
                    dst_dir_fd=self._directory_fd,
                )
            except OSError:
                claim_may_exist = False
                return
            try:
                data = _read_mailbox_file(self._directory_fd, processing)
                request = _strict_json_loads(data)
                if (
                    not isinstance(request, Mapping)
                    or request.get("request_id") != request_id
                ):
                    raise LiveBrokerError(
                        "Live mailbox request id does not match its filename"
                    )
                operation = request.get("operation")
                is_flag = operation == "agent.flag"
                is_read = self.service.is_read_only_request(
                    operation,
                    request.get("params", {}),
                )
                if (
                    not is_flag
                    and not is_read
                    and not self._operation_idle.is_set()
                ):
                    os.rename(
                        processing,
                        name,
                        src_dir_fd=self._directory_fd,
                        dst_dir_fd=self._directory_fd,
                    )
                    self._deferred_operation_names.add(name)
                    handed_off = True
                    return
                if is_read:
                    read_permit = self._reserve_read_lane()
                    if read_permit is None:
                        os.rename(
                            processing,
                            name,
                            src_dir_fd=self._directory_fd,
                            dst_dir_fd=self._directory_fd,
                        )
                        handed_off = True
                        return
                    release_reserved_lane = read_permit.release
                self._reserve_request_id(request_id)
                if is_flag:
                    self._dispatch_claimed(
                        processing,
                        request_id,
                        request,
                        background=False,
                    )
                    handed_off = True
                    return
                # Publish submitter ownership before clearing the lane. If a
                # control interruption lands before the dispatch handoff is
                # resolved, the outer finally either cancels the still-pending
                # callable or recognizes that the worker already owns it.
                if not is_read:
                    self._operation_idle.clear()
                    release_reserved_lane = self._operation_idle.set
                assert release_reserved_lane is not None
                dispatch = _BackgroundRequestDispatch(
                    self,
                    processing,
                    request_id,
                    request,
                    release_lane=release_reserved_lane,
                )
                try:
                    assert self._operation_executor is not None
                    self._operation_executor.submit(dispatch)
                except BaseException:
                    if dispatch.cancel_before_worker_start():
                        release_reserved_lane()
                        release_reserved_lane = None
                    else:
                        # The worker already owns processing and its lane.
                        handed_off = True
                        release_reserved_lane = None
                    raise
                handed_off = True
                release_reserved_lane = None
                return
            except (
                UnicodeError,
                json.JSONDecodeError,
                LiveBrokerError,
                RuntimeError,
                ValueError,
                OSError,
            ) as error:
                response = {
                    "schema_version": 1,
                    "request_id": request_id,
                    "ok": False,
                    "error": str(error)[:4096] or "Live broker operation failed",
                }
            cleanup_attempted = True
            self._remove_claimed_request(processing)
            handed_off = True
            self._write_response(request_id, response)
        finally:
            if release_reserved_lane is not None and not handed_off:
                if (
                    dispatch is not None
                    and not dispatch.cancel_before_worker_start()
                ):
                    # submit() crossed its ambiguous return boundary and the
                    # worker already owns the exact claimed request.
                    handed_off = True
                else:
                    release_reserved_lane()
            if (
                claim_may_exist
                and not handed_off
                and not cleanup_attempted
            ):
                active_error = sys.exception()
                try:
                    self._remove_claimed_request(processing)
                except BaseException as cleanup_error:
                    if active_error is None:
                        raise
                    active_error.add_note(
                        "Live broker claimed request cleanup failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                names = self._request_names()
            except Exception as error:
                self._set_terminal_error(error)
                return
            self._deferred_operation_names.intersection_update(names)
            if not names:
                self._stop.wait(0.02)
                continue
            for name in names:
                if self._stop.is_set():
                    break
                if (
                    name in self._deferred_operation_names
                    and not self._operation_idle.is_set()
                ):
                    continue
                match = _REQUEST_NAME.fullmatch(name)
                request_id = match.group(1) if match is not None else ""
                try:
                    self._process(name)
                except Exception as error:
                    # A hostile response entry can make os.replace fail. Keep
                    # the watcher alive and signal only this request through a
                    # separate bounded file.
                    try:
                        self._write_request_failure(request_id, error)
                    except Exception as signal_error:
                        self._set_terminal_error(
                            LiveBrokerError(
                                "Live broker could not publish a request "
                                f"failure: {signal_error}"
                            )
                        )
                        return
                except BaseException as error:
                    # KeyboardInterrupt/SystemExit in this daemon thread
                    # cannot be propagated to the parent TUI. Publish an
                    # explicit terminal state so current and subsequent RPCs
                    # fail promptly instead of silently timing out.
                    self._set_terminal_error(
                        LiveBrokerError(
                            "Live broker watcher was interrupted: "
                            f"{type(error).__name__}: "
                            f"{str(error)[:4096] or 'no detail'}"
                        )
                    )
                    return

    def start(self) -> LiveBrokerServer:
        if (
            self._directory_fd is not None
            or self._operation_executor is not None
            or self._thread is not None
        ):
            raise RuntimeError("Live broker server is already started")
        self._stop.clear()
        pending_directory_fds: list[int] = []
        try:
            self._directory_fd = _open_private_directory(
                self.directory,
                pending_handoff=pending_directory_fds,
            )
            pending_directory_fds.clear()
            self._operation_executor = ThreadPoolExecutor(
                # One mutation lane plus a bounded set of independent
                # read-only snapshots. Admission below prevents an unbounded
                # executor queue.
                max_workers=1 + MAX_CONCURRENT_READ_ONLY_OPERATIONS,
                thread_name_prefix=(
                    "ctfos-live-operation-"
                    f"{self.service.expected_scope[:12]}"
                ),
            )
            self._thread = threading.Thread(
                target=self._serve,
                name=(
                    "ctfos-live-broker-"
                    f"{self.service.expected_scope[:12]}"
                ),
                daemon=True,
            )
            self._write_status("ready")
            self._thread.start()
        except BaseException as error:
            if (
                self._directory_fd is None
                and pending_directory_fds
            ):
                self._directory_fd = pending_directory_fds[0]
            pending_directory_fds.clear()
            propagated_error = error
            try:
                cleanup_errors = self._cleanup_lifecycle(
                    write_closing_status=False,
                )
            except BaseException as cleanup_error:
                cleanup_errors = [
                    ("lifecycle cleanup", cleanup_error),
                ]
            for label, cleanup_error in cleanup_errors:
                propagated_error = _prefer_control_error(
                    propagated_error,
                    cleanup_error,
                    label=f"Live broker {label} cleanup failed",
                )
            if propagated_error is not error:
                raise propagated_error
            raise
        return self

    def __enter__(self) -> LiveBrokerServer:
        if (
            self._directory_fd is not None
            or self._operation_executor is not None
            or self._thread is not None
        ):
            raise RuntimeError("Live broker server is already started")
        # Resource acquisition happens explicitly inside the with body.
        return self

    def __exit__(
        self,
        exception_type: object,
        exception: object,
        _traceback: object,
    ) -> None:
        # Do not release the parent session lock or close the mailbox while a
        # dispatched tool/state operation is active. Tool execution has its
        # own explicit bound.
        cleanup_errors = self._cleanup_lifecycle(
            write_closing_status=True,
        )
        active_error = (
            exception if isinstance(exception, BaseException) else None
        )
        if active_error is not None:
            cleanup_control = next(
                (
                    cleanup_error
                    for _label, cleanup_error in cleanup_errors
                    if not isinstance(cleanup_error, Exception)
                ),
                None,
            )
            if (
                cleanup_control is not None
                and isinstance(active_error, Exception)
            ):
                cleanup_control.add_note(
                    "Live broker cleanup interrupted an active "
                    f"{type(active_error).__name__}: {active_error}"
                )
                for label, cleanup_error in cleanup_errors:
                    if cleanup_error is cleanup_control:
                        continue
                    cleanup_control.add_note(
                        f"additional Live broker {label} cleanup failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
                raise cleanup_control
            for label, cleanup_error in cleanup_errors:
                active_error.add_note(
                    f"Live broker {label} cleanup failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            return
        if cleanup_errors:
            primary_index = next(
                (
                    index
                    for index, (_label, error) in enumerate(cleanup_errors)
                    if not isinstance(error, Exception)
                ),
                0,
            )
            label, cleanup_error = cleanup_errors[primary_index]
            for index, (
                additional_label,
                additional_error,
            ) in enumerate(cleanup_errors):
                if index == primary_index:
                    continue
                cleanup_error.add_note(
                    f"additional Live broker {additional_label} cleanup "
                    f"failed: {type(additional_error).__name__}: "
                    f"{additional_error}"
                )
            cleanup_error.add_note(
                f"Live broker cleanup step: {label}"
            )
            raise cleanup_error
        if self._terminal_error is not None and exception_type is None:
            raise self._terminal_error


class LiveBrokerDirectoryOwner:
    """Resource-free guard for one private MCP-bridge session leaf."""

    def __init__(self, runtime_directory: Path) -> None:
        self.runtime_directory = runtime_directory
        self.session_name = f"session-{uuid.uuid4().hex}"
        self.directory = (
            runtime_directory / "live-mailboxes" / self.session_name
        )
        self._runtime_fd: int | None = None
        self._mailboxes_fd: int | None = None
        self._cleanup_fd: int | None = None
        self._allocated = False

    @staticmethod
    def _close_owned_fd(
        owner: LiveBrokerDirectoryOwner,
        attribute: str,
    ) -> BaseException | None:
        descriptor = getattr(owner, attribute)
        if descriptor is None:
            return None
        # The directory may be reopened by a legitimate peer at the same inode
        # and numeric fd while close returns.  Consume this owner's reference
        # first and never retry the ambiguous integer.
        setattr(owner, attribute, None)
        try:
            os.close(descriptor)
        except BaseException as error:
            return error
        return None

    def _open_owned_directory(
        self,
        attribute: str,
        path: str | Path,
        flags: int,
        *,
        pending_handoff: list[tuple[str, int]],
        dir_fd: int | None = None,
    ) -> None:
        descriptor = os.open(path, flags, dir_fd=dir_fd)
        pending_handoff.append((attribute, descriptor))
        setattr(self, attribute, descriptor)
        pending_handoff.pop()

    def allocate(self) -> Path:
        if self._allocated:
            raise RuntimeError("Live broker directory owner is already used")
        self._allocated = True
        runtime_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
        runtime_flags |= getattr(os, "O_NOFOLLOW", 0)
        pending_fds: list[tuple[str, int]] = []
        try:
            self._open_owned_directory(
                "_runtime_fd",
                self.runtime_directory,
                runtime_flags,
                pending_handoff=pending_fds,
            )
            assert self._runtime_fd is not None
            runtime_metadata = os.fstat(self._runtime_fd)
            if (
                not stat.S_ISDIR(runtime_metadata.st_mode)
                or runtime_metadata.st_uid != os.geteuid()
            ):
                raise LiveBrokerError(
                    "challenge runtime must be an owned directory"
                )
            try:
                os.mkdir(
                    "live-mailboxes",
                    0o700,
                    dir_fd=self._runtime_fd,
                )
            except FileExistsError:
                pass
            self._open_owned_directory(
                "_mailboxes_fd",
                "live-mailboxes",
                runtime_flags,
                pending_handoff=pending_fds,
                dir_fd=self._runtime_fd,
            )
            assert self._mailboxes_fd is not None
            mailbox_metadata = os.fstat(self._mailboxes_fd)
            if (
                not stat.S_ISDIR(mailbox_metadata.st_mode)
                or mailbox_metadata.st_uid != os.geteuid()
                or mailbox_metadata.st_mode & 0o077
            ):
                raise LiveBrokerError(
                    "Live mailbox root must be a private owned directory"
                )
            os.mkdir(
                self.session_name,
                0o700,
                dir_fd=self._mailboxes_fd,
            )
            self._open_owned_directory(
                "_cleanup_fd",
                self.session_name,
                runtime_flags,
                pending_handoff=pending_fds,
                dir_fd=self._mailboxes_fd,
            )
            assert self._cleanup_fd is not None
            session_metadata = os.fstat(self._cleanup_fd)
            if (
                not stat.S_ISDIR(session_metadata.st_mode)
                or session_metadata.st_uid != os.geteuid()
                or session_metadata.st_mode & 0o077
            ):
                raise LiveBrokerError(
                    "Live session mailbox must be a private owned directory"
                )
        except BaseException as error:
            for attribute, descriptor in pending_fds:
                if getattr(self, attribute) is None:
                    setattr(self, attribute, descriptor)
            pending_fds.clear()
            try:
                self.close()
            except BaseException as cleanup_error:
                propagated_error = _prefer_control_error(
                    error,
                    cleanup_error,
                    label=(
                        "Live broker directory allocation cleanup failed"
                    ),
                )
                if propagated_error is not error:
                    raise propagated_error
            raise
        return self.directory

    def close(self) -> None:
        errors: list[tuple[str, BaseException]] = []
        cleanup_fd = self._cleanup_fd
        if cleanup_fd is not None:
            try:
                with os.scandir(cleanup_fd) as entries:
                    for index, entry in enumerate(entries):
                        if index >= MAX_MAILBOX_SCAN_ENTRIES:
                            break
                        try:
                            os.unlink(entry.name, dir_fd=cleanup_fd)
                        except OSError:
                            # Never recurse through model-created entries.
                            pass
            except OSError:
                pass
            except BaseException as error:
                errors.append(("session scan", error))
            close_error = self._close_owned_fd(self, "_cleanup_fd")
            if close_error is not None:
                errors.append(("session fd close", close_error))
        mailboxes_fd = self._mailboxes_fd
        if mailboxes_fd is not None:
            try:
                os.rmdir(self.session_name, dir_fd=mailboxes_fd)
            except OSError:
                # A hostile subdirectory may intentionally prevent cleanup.
                pass
            except BaseException as error:
                errors.append(("session directory removal", error))
            close_error = self._close_owned_fd(
                self,
                "_mailboxes_fd",
            )
            if close_error is not None:
                errors.append(("mailbox root fd close", close_error))
        runtime_fd = self._runtime_fd
        if runtime_fd is not None:
            try:
                os.rmdir("live-mailboxes", dir_fd=runtime_fd)
            except OSError:
                pass
            except BaseException as error:
                errors.append(("mailbox root removal", error))
            close_error = self._close_owned_fd(self, "_runtime_fd")
            if close_error is not None:
                errors.append(("runtime fd close", close_error))
        if errors:
            primary_label, primary_error = errors[0]
            for additional_label, additional_error in errors[1:]:
                preferred_error = _prefer_control_error(
                    primary_error,
                    additional_error,
                    label=(
                        "additional Live broker directory cleanup failure "
                        f"at {additional_label}"
                    ),
                )
                if preferred_error is additional_error:
                    primary_label = additional_label
                primary_error = preferred_error
            primary_error.add_note(
                f"Live broker directory cleanup step: {primary_label}"
            )
            raise primary_error

    def __enter__(self) -> LiveBrokerDirectoryOwner:
        if self._allocated:
            raise RuntimeError("Live broker directory owner is already used")
        # No file descriptor or directory leaf exists at this return boundary.
        return self

    def __exit__(
        self,
        _exception_type: object,
        exception: object,
        _traceback: object,
    ) -> None:
        try:
            self.close()
        except BaseException as cleanup_error:
            if isinstance(exception, BaseException):
                propagated_error = _prefer_control_error(
                    exception,
                    cleanup_error,
                    label="Live broker directory cleanup failed",
                )
                if propagated_error is not exception:
                    raise propagated_error
                return
            raise

    def __del__(self) -> None:
        try:
            self.close()
        except BaseException:
            pass


def allocated_live_broker_directory(
    runtime_directory: Path,
) -> LiveBrokerDirectoryOwner:
    """Return a resource-free owner; call allocate inside its with body."""

    return LiveBrokerDirectoryOwner(runtime_directory)


class LiveBrokerClient:
    """Bounded client used before constructing any local engine objects."""

    def __init__(self, directory: Path, token: str) -> None:
        path = directory.expanduser()
        if (
            not path.is_absolute()
            or "\x00" in str(path)
            or len(os.fsencode(path)) > 4096
        ):
            raise LiveBrokerError("invalid Live broker mailbox path")
        if not token or len(token.encode("utf-8")) > 8192 or "\n" in token:
            raise LiveBrokerError("invalid Live broker capability")
        self.directory = path
        self.token = token

    @classmethod
    def from_environment(cls) -> LiveBrokerClient | None:
        marker = os.environ.get(LIVE_SESSION_ENV)
        directory_value = os.environ.get(LIVE_BROKER_DIRECTORY_ENV)
        token = os.environ.get(LIVE_SCOPE_CAPABILITY_ENV)
        if marker is None and directory_value is None and token is None:
            return None
        if marker != "1" or not directory_value or not token:
            raise LiveBrokerError(
                "incomplete Live broker environment; refusing local fallback"
            )
        return cls(Path(directory_value), token)

    def call(
        self,
        operation: str,
        identity: ChallengeIdentity,
        params: Mapping[str, object] | None = None,
        *,
        timeout: float = (
            MAX_LIVE_OPERATION_SECONDS + MAX_LIVE_CLIENT_GRACE_SECONDS
        ),
    ) -> object:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or not 0 < timeout <= (
                MAX_LIVE_OPERATION_SECONDS
                + MAX_LIVE_CLIENT_GRACE_SECONDS
            )
        ):
            raise LiveBrokerError(
                "Live broker timeout must be positive and at most "
                f"{MAX_LIVE_OPERATION_SECONDS + MAX_LIVE_CLIENT_GRACE_SECONDS} "
                "seconds"
            )
        request_id = uuid.uuid4().hex
        request = {
            "schema_version": 1,
            "request_id": request_id,
            "token": self.token,
            "identity": identity.to_dict(),
            "operation": operation,
            "params": dict(params or {}),
        }
        payload = _encode_message(request)
        request_name = f"request-{request_id}.json"
        response_name = f"response-{request_id}.json"
        error_name = f"error-{request_id}.json"
        directory_owner = _LiveBrokerDirectoryFd()
        directory_fd: int | None = None
        try:
            # The resource-free owner and outer cleanup guard both exist
            # before open. A control exception at either helper return/store
            # boundary therefore cannot lose the mailbox descriptor.
            directory_fd = directory_owner.open(self.directory)
            status = _strict_json_loads(
                _read_mailbox_file(directory_fd, _SERVER_STATUS_NAME)
            )
            if (
                not isinstance(status, Mapping)
                or status.get("schema_version") != 1
                or status.get("state") != "ready"
                or not isinstance(status.get("session_id"), str)
            ):
                raise LiveBrokerError("Live broker server is not ready")
            session_id = status["session_id"]
            _atomic_mailbox_write(directory_fd, request_name, payload)
            deadline = time.monotonic() + timeout
            while True:
                try:
                    data = _read_mailbox_file(directory_fd, response_name)
                    break
                except LiveBrokerError as error:
                    # The response may be published between the first
                    # pathname lookup in _read_mailbox_file() and this
                    # existence check.  In that benign race the original
                    # ENOENT is still the reason the read failed even though
                    # the second lookup now succeeds, so retry instead of
                    # misclassifying a freshly published response as hostile.
                    missing_during_read = isinstance(
                        error.__cause__,
                        FileNotFoundError,
                    )
                    try:
                        os.stat(
                            response_name,
                            dir_fd=directory_fd,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        try:
                            failure = _strict_json_loads(
                                _read_mailbox_file(directory_fd, error_name)
                            )
                        except (
                            FileNotFoundError,
                            UnicodeError,
                            json.JSONDecodeError,
                            LiveBrokerError,
                        ):
                            failure = None
                        if (
                            isinstance(failure, Mapping)
                            and failure.get("schema_version") == 1
                            and failure.get("request_id") == request_id
                        ):
                            raise LiveBrokerError(
                                str(
                                    failure.get(
                                        "error",
                                        "Live broker request failed",
                                    )
                                )
                            )
                        try:
                            current_status = _strict_json_loads(
                                _read_mailbox_file(
                                    directory_fd,
                                    _SERVER_STATUS_NAME,
                                )
                            )
                        except (
                            UnicodeError,
                            json.JSONDecodeError,
                            LiveBrokerError,
                        ):
                            current_status = None
                        if (
                            isinstance(current_status, Mapping)
                            and (
                                current_status.get("session_id") != session_id
                                or current_status.get("state") != "ready"
                            )
                        ):
                            raise LiveBrokerError(
                                str(
                                    current_status.get(
                                        "error",
                                        "Live broker server stopped",
                                    )
                                )
                            )
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise LiveBrokerError(
                                "Live broker request timed out"
                            ) from error
                        time.sleep(min(0.02, remaining))
                        continue
                    if missing_during_read:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise LiveBrokerError(
                                "Live broker request timed out"
                            ) from error
                        time.sleep(min(0.02, remaining))
                        continue
                    raise
            try:
                os.unlink(response_name, dir_fd=directory_fd)
            except OSError:
                pass
        except OSError as error:
            raise LiveBrokerError(f"Live broker request failed: {error}") from error
        finally:
            active_error = sys.exception()
            cleanup_errors: list[tuple[str, BaseException]] = []
            if directory_fd is not None:
                try:
                    for name in (
                        request_name,
                        response_name,
                        error_name,
                    ):
                        try:
                            os.unlink(name, dir_fd=directory_fd)
                        except OSError:
                            pass
                except BaseException as cleanup_error:
                    cleanup_errors.append(
                        ("mailbox entry cleanup", cleanup_error)
                    )
            close_error = directory_owner.close()
            if close_error is not None:
                cleanup_errors.append(("directory close", close_error))
            if cleanup_errors:
                cleanup_control = next(
                    (
                        error
                        for _label, error in cleanup_errors
                        if not isinstance(error, Exception)
                    ),
                    None,
                )
                if (
                    cleanup_control is not None
                    and active_error is not None
                    and isinstance(active_error, Exception)
                ):
                    cleanup_control.add_note(
                        "Live broker client cleanup interrupted an active "
                        f"{type(active_error).__name__}: "
                        f"{active_error}"
                    )
                    for label, error in cleanup_errors:
                        if error is not cleanup_control:
                            cleanup_control.add_note(
                                f"additional Live broker client {label} "
                                f"failure: {type(error).__name__}: {error}"
                            )
                    raise cleanup_control
                if active_error is not None:
                    for label, error in cleanup_errors:
                        active_error.add_note(
                            f"Live broker client {label} failed: "
                            f"{type(error).__name__}: {error}"
                        )
                else:
                    primary = cleanup_control or cleanup_errors[0][1]
                    for label, error in cleanup_errors:
                        if error is not primary:
                            primary.add_note(
                                f"additional Live broker client {label} "
                                f"failure: {type(error).__name__}: {error}"
                            )
                    raise primary
        try:
            response = _strict_json_loads(data)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise LiveBrokerError("Live broker returned invalid JSON") from error
        if (
            not isinstance(response, Mapping)
            or response.get("schema_version") != 1
            or response.get("request_id") != request_id
        ):
            raise LiveBrokerError("Live broker returned an unsupported response")
        if response.get("ok") is not True:
            raise LiveBrokerError(str(response.get("error", "Live operation failed")))
        return response.get("result")


__all__ = [
    "LIVE_BROKER_DIRECTORY_ENV",
    "LIVE_SCOPE_CAPABILITY_ENV",
    "LIVE_SESSION_ENV",
    "LiveBrokerClient",
    "LiveBrokerError",
    "LiveBrokerServer",
    "LiveBrokerService",
    "allocated_live_broker_directory",
]
