"""Append-only authoritative race lineage and deterministic projections.

Python records and validates lifecycle evidence.  It never starts or stops a
native model session; NATIVE_STARTED and NATIVE_STOP_RECORDED are observations
submitted by the user-opened Sol session.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path
from typing import Any

from .attempts import canonical_json
from .modes import SolveMode, maximum_child_width
from .workspace import (
    WorkspaceError, append_jsonl_fsync, atomic_json, read_jsonl_strict,
    resolve_active_run, state_lock, utc_now,
)


LINEAGE_SCHEMA_VERSION = 1
LINEAGE_FILE = "RACE_LINEAGE.jsonl"
LIFECYCLE_EVENTS = frozenset({
    "PLANNED", "CAPACITY_ADMITTED", "SANDBOX_READY", "AWAITING_NATIVE_START",
    "NATIVE_STARTED", "RUNNING", "CHECKPOINTED", "STOP_REQUESTED",
    "NATIVE_STOP_RECORDED", "CHILD_TERMINAL_RESULT_RECORDED", "SANDBOX_CLEANED",
    "RESOURCE_RELEASED", "START_FAILED", "SUPERSEDED", "TERMINAL",
})
STARTED_EVENTS = frozenset({"NATIVE_STARTED", "RUNNING", "CHECKPOINTED", "STOP_REQUESTED"})
TERMINAL_EVIDENCE = frozenset({"NATIVE_STOP_RECORDED", "CHILD_TERMINAL_RESULT_RECORDED"})

_ALLOWED: dict[str | None, set[str]] = {
    None: {"PLANNED"},
    "PLANNED": {"CAPACITY_ADMITTED", "START_FAILED", "SUPERSEDED"},
    "CAPACITY_ADMITTED": {"SANDBOX_READY", "START_FAILED", "SUPERSEDED"},
    "SANDBOX_READY": {"AWAITING_NATIVE_START", "START_FAILED", "SUPERSEDED"},
    "AWAITING_NATIVE_START": {"NATIVE_STARTED", "START_FAILED", "SUPERSEDED"},
    "NATIVE_STARTED": {"RUNNING", "STOP_REQUESTED", "NATIVE_STOP_RECORDED", "CHILD_TERMINAL_RESULT_RECORDED"},
    "RUNNING": {"CHECKPOINTED", "STOP_REQUESTED", "NATIVE_STOP_RECORDED", "CHILD_TERMINAL_RESULT_RECORDED"},
    "CHECKPOINTED": {"RUNNING", "STOP_REQUESTED", "NATIVE_STOP_RECORDED", "CHILD_TERMINAL_RESULT_RECORDED"},
    "STOP_REQUESTED": {"NATIVE_STOP_RECORDED", "CHILD_TERMINAL_RESULT_RECORDED"},
    "NATIVE_STOP_RECORDED": {"CHILD_TERMINAL_RESULT_RECORDED", "SANDBOX_CLEANED", "RESOURCE_RELEASED", "SUPERSEDED", "TERMINAL"},
    "CHILD_TERMINAL_RESULT_RECORDED": {"NATIVE_STOP_RECORDED", "SANDBOX_CLEANED", "RESOURCE_RELEASED", "SUPERSEDED", "TERMINAL"},
    "SANDBOX_CLEANED": {"RESOURCE_RELEASED", "SUPERSEDED", "TERMINAL"},
    "RESOURCE_RELEASED": {"SANDBOX_CLEANED", "SUPERSEDED", "TERMINAL"},
    "START_FAILED": {"SANDBOX_CLEANED", "RESOURCE_RELEASED", "SUPERSEDED", "TERMINAL"},
    "SUPERSEDED": {"SANDBOX_CLEANED", "RESOURCE_RELEASED", "TERMINAL"},
    "TERMINAL": set(),
}


class LineageError(ValueError):
    pass


def lineage_path(root: Path) -> Path:
    return _lineage_root(root) / LINEAGE_FILE


def load_lineage(root: Path) -> list[dict[str, Any]]:
    run = _lineage_root(root)
    rows = read_jsonl_strict(run / LINEAGE_FILE, "race lineage ledger")
    seen_events: dict[str, bytes] = {}
    native_sessions: dict[str, str] = {}
    branches: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        _validate_row(row, run)
        event_id = str(row["lineage_event_id"])
        encoded = canonical_json(row)
        if event_id in seen_events and seen_events[event_id] != encoded:
            raise LineageError("lineage_event_id has conflicting canonical material")
        seen_events[event_id] = encoded
        branch_key = str(row["lineage_branch_id"])
        session_id = str(row["session_id"])
        if row["event"] == "NATIVE_STARTED":
            if session_id in native_sessions and native_sessions[session_id] != branch_key:
                raise LineageError("one native session_id resolves to multiple started lineage branches")
            native_sessions[session_id] = branch_key
        history = branches.setdefault(branch_key, [])
        if history and not _transition_allowed(history, row):
            raise LineageError(
                f"invalid lineage transition {history[-1]['event']} -> {row['event']}"
            )
        history.append(row)
    return rows


def lineage_state(root: Path) -> dict[str, Any]:
    run = _lineage_root(root)
    rows = load_lineage(run)
    histories: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        histories.setdefault(str(row["lineage_branch_id"]), []).append(row)
    branches: list[dict[str, Any]] = []
    for history in histories.values():
        first, latest = history[0], history[-1]
        events = [str(row["event"]) for row in history]
        details = dict(first.get("details") or {})
        contract = dict(details.get("branch_contract") or {})
        branches.append({
            **contract,
            "lineage_branch_id": first["lineage_branch_id"],
            "lineage_id": first["lineage_id"], "race_id": first["race_id"],
            "generation": first["generation"], "branch_id": first["branch_id"],
            "session_id": first["session_id"], "parent_branch_id": first["parent_branch_id"],
            "supersedes_branch_id": first["supersedes_branch_id"],
            "hypothesis_family": first["hypothesis_family"], "mode": first["mode"],
            "challenge_id": first.get("challenge_id"),
            "input_fingerprint": first.get("input_fingerprint"),
            "target_revision": first.get("target_revision"),
            "status": latest["event"], "created_at": first["created_at"],
            "updated_at": latest["created_at"], "lifecycle_history": history,
            "started": any(event in STARTED_EVENTS for event in events),
            "native_started": "NATIVE_STARTED" in events,
            "terminal_evidence_recorded": any(event in TERMINAL_EVIDENCE for event in events),
            "sandbox_cleaned": "SANDBOX_CLEANED" in events,
            "resource_released": "RESOURCE_RELEASED" in events,
            "terminal": latest["event"] == "TERMINAL",
            "start_receipt": _event_details(history, "NATIVE_STARTED"),
            "native_stop_receipt": _event_details(history, "NATIVE_STOP_RECORDED"),
            "terminal_result_receipt": _event_details(history, "CHILD_TERMINAL_RESULT_RECORDED"),
        })
    branches.sort(key=lambda row: (int(row["generation"]), str(row["branch_id"])))
    generations = sorted({int(row["generation"]) for row in branches})
    current_generation = generations[-1] if generations else None
    current = [row for row in branches if row["generation"] == current_generation]
    active = [row for row in branches if row["status"] == "RUNNING"]
    orphan = [
        row["session_id"] for row in branches
        if row["native_started"] and row["status"] in {"SUPERSEDED", "TERMINAL", "START_FAILED"}
        and not row["terminal_evidence_recorded"]
    ]
    return {
        "schema_version": LINEAGE_SCHEMA_VERSION,
        "run_id": run.name,
        "current_generation": current_generation,
        "prior_generations": generations[:-1],
        "generations": generations,
        "branches": branches,
        "current_branches": current,
        "planned_width": sum(row["status"] != "TERMINAL" for row in current),
        "active_width": len(active),
        "active_branches": active,
        "orphan_native_sessions": orphan,
        "terminal_convergence_targets": [
            row["session_id"] for row in branches
            if row["native_started"] or not row["sandbox_cleaned"] or not row["resource_released"]
        ],
    }


def append_lineage_event(
    root: Path,
    *,
    event: str,
    branch_id: str,
    session_id: str | None = None,
    race_id: str | None = None,
    generation: int | None = None,
    lineage_id: str | None = None,
    parent_branch_id: str | None = None,
    supersedes_branch_id: str | None = None,
    hypothesis_family: str | None = None,
    mode: SolveMode | str | None = None,
    referenced_receipt: Mapping[str, Any] | None = None,
    referenced_receipt_digest: str | None = None,
    details: Mapping[str, Any] | None = None,
    operation_id: str | None = None,
    project: bool = True,
) -> dict[str, Any]:
    run = _lineage_root(root)
    normalized_event = str(event).upper()
    if normalized_event not in LIFECYCLE_EVENTS:
        raise LineageError(f"unsupported lineage event: {event}")
    identity = _run_identity(run)
    with state_lock(run):
        existing_rows = load_lineage(run)
        matching = [row for row in existing_rows if row["branch_id"] == branch_id]
        if generation is not None:
            branch_rows = [row for row in matching if row["generation"] == generation]
        elif matching:
            latest_generation = max(int(row["generation"]) for row in matching)
            branch_rows = [row for row in matching if row["generation"] == latest_generation]
        else:
            branch_rows = []
        if branch_rows:
            first = branch_rows[0]
            values = {
                "session_id": session_id or first["session_id"],
                "race_id": race_id or first["race_id"],
                "generation": generation if generation is not None else first["generation"],
                "lineage_id": lineage_id or first["lineage_id"],
                "parent_branch_id": parent_branch_id if parent_branch_id is not None else first["parent_branch_id"],
                "supersedes_branch_id": supersedes_branch_id if supersedes_branch_id is not None else first["supersedes_branch_id"],
                "hypothesis_family": hypothesis_family or first["hypothesis_family"],
                "mode": SolveMode(mode).value if mode is not None else first["mode"],
            }
        else:
            if normalized_event != "PLANNED":
                raise LineageError("a lineage branch must begin with PLANNED")
            if generation is None or generation < 1 or not race_id or not hypothesis_family or mode is None:
                raise LineageError("PLANNED requires race, generation, hypothesis family, and mode")
            values = {
                "session_id": session_id or branch_id,
                "race_id": race_id,
                "generation": generation,
                "lineage_id": lineage_id or f"lineage-{identity['attempt_id']}",
                "parent_branch_id": parent_branch_id,
                "supersedes_branch_id": supersedes_branch_id,
                "hypothesis_family": hypothesis_family,
                "mode": SolveMode(mode).value,
            }
        lineage_branch_id = f"{values['lineage_id']}:{values['generation']}:{branch_id}"
        if branch_rows and branch_rows[0]["lineage_branch_id"] != lineage_branch_id:
            raise LineageError("branch canonical lineage identity conflicts with prior events")
        receipt_digest = referenced_receipt_digest or hashlib.sha256(
            canonical_json(dict(referenced_receipt or details or {"event": normalized_event}))
        ).hexdigest()
        if len(receipt_digest) != 64 or any(
            character not in "0123456789abcdef" for character in receipt_digest
        ):
            raise LineageError("referenced receipt digest must be exact lowercase SHA-256")
        material = {
            **identity,
            "lineage_id": values["lineage_id"], "race_id": values["race_id"],
            "generation": values["generation"], "branch_id": branch_id,
            "lineage_branch_id": lineage_branch_id, "session_id": values["session_id"],
            "parent_branch_id": values["parent_branch_id"],
            "supersedes_branch_id": values["supersedes_branch_id"],
            "hypothesis_family": values["hypothesis_family"], "mode": values["mode"],
            "event": normalized_event, "referenced_receipt_digest": receipt_digest,
            "details": dict(details or referenced_receipt or {}),
            "operation_id": operation_id,
        }
        event_id = hashlib.sha256(canonical_json(material)).hexdigest()[:32]
        duplicate = next((row for row in existing_rows if row["lineage_event_id"] == event_id), None)
        if duplicate:
            return {**duplicate, "idempotent": True}
        history = [row for row in existing_rows if row["lineage_branch_id"] == lineage_branch_id]
        probe = {**material, "lineage_event_id": event_id}
        if not _transition_allowed(history, probe):
            before = history[-1]["event"] if history else None
            raise LineageError(f"invalid lineage transition {before} -> {normalized_event}")
        _validate_semantics(history, probe, existing_rows, run=run)
        record = {
            "schema_version": LINEAGE_SCHEMA_VERSION,
            "lineage_event_id": event_id,
            "receipt_id": event_id,
            **material,
            "created_at": utc_now(),
        }
        append_jsonl_fsync(run / LINEAGE_FILE, record, label="race lineage ledger")
    if project:
        recover_lineage_projections(run)
    return {**record, "idempotent": False}


def plan_race_generation(
    root: Path,
    *,
    race_id: str,
    mode: SolveMode | str,
    parent_session_id: str,
    branches: Sequence[Mapping[str, Any]],
    legacy_tier: int | None = None,
    tier_reason: str = "",
    frozen_template: bool = False,
    legacy_compatibility: bool = False,
) -> dict[str, Any]:
    run = _lineage_root(root)
    selected = SolveMode(mode)
    from .modes import validate_branch_intents

    if not legacy_compatibility:
        validate_branch_intents(selected, len(branches), frozen_template=frozen_template)
    current = lineage_state(run)
    run_state = json.loads((run / "STATE.json").read_text(encoding="utf-8"))
    legacy_board_view = bool(legacy_compatibility and not run_state.get("run_id"))
    generation = (current["current_generation"] or 0) + 1
    if current["current_branches"]:
        unconverged: list[dict[str, Any]] = []
        for branch in current["current_branches"]:
            if branch["status"] == "TERMINAL":
                continue
            if branch["started"]:
                if not (
                    branch["terminal_evidence_recorded"]
                    and branch["sandbox_cleaned"] and branch["resource_released"]
                ):
                    unconverged.append(branch)
        if unconverged:
            from .control import create_control_action

            for branch in unconverged:
                if branch["status"] in {"NATIVE_STARTED", "RUNNING", "CHECKPOINTED"}:
                    append_lineage_event(
                        run, event="STOP_REQUESTED", branch_id=str(branch["branch_id"]),
                        details={
                            "reason": "WHOLE_PLAN_RESTART_REQUIRES_CONVERGENCE",
                            "requested_race_id": race_id,
                        }, project=False,
                    )
                create_control_action(
                    run, session_id=str(branch["session_id"]), action_type="STOP_REQUIRED",
                    reason="whole-plan restart requires exact native terminal, sandbox cleanup, and resource release receipts",
                    triggering_evidence_id=f"replan:{race_id}:generation:{generation}",
                    evidence_generation=generation,
                    metadata={
                        "requested_race_id": race_id,
                        "prior_generation": branch["generation"],
                        "branch_id": branch["branch_id"],
                    },
                )
            recover_lineage_projections(run)
            raise LineageError(
                "whole-plan restart rejected: prior started branch lacks exact stop/terminal, cleanup, or release receipt"
            )
        for branch in current["current_branches"]:
            if branch["status"] == "TERMINAL":
                continue
            append_lineage_event(
                run, event="SUPERSEDED", branch_id=str(branch["branch_id"]),
                details={"reason": "WHOLE_PLAN_RESTART", "not_started": not branch["started"]},
                project=False,
            )
            append_lineage_event(
                run, event="TERMINAL", branch_id=str(branch["branch_id"]),
                details={"reason": "NOT_STARTED_SUPERSEDED" if not branch["started"] else "SUPERSEDED_AFTER_CONVERGENCE"},
                project=False,
            )
    for row in branches:
        branch_id = str(row.get("branch_id") or row.get("session_id") or "")
        if not branch_id:
            raise LineageError("branch intent requires branch_id or session_id")
        append_lineage_event(
            run, event="PLANNED", branch_id=branch_id,
            session_id=str(row.get("session_id") or branch_id), race_id=race_id,
            generation=generation, parent_branch_id=str(row.get("parent_branch_id") or parent_session_id),
            supersedes_branch_id=(str(row["supersedes_branch_id"]) if row.get("supersedes_branch_id") else None),
            hypothesis_family=str(row.get("hypothesis_family") or "independent-full-solve"),
            mode=selected,
            details={
                "branch_contract": dict(row), "legacy_tier": legacy_tier,
                "tier_reason": tier_reason,
                "frozen_template": bool(frozen_template),
                "legacy_compatibility": bool(legacy_compatibility),
                "legacy_board_view": legacy_board_view,
            },
            project=False,
        )
    return recover_lineage_projections(run)


def recover_lineage_projections(root: Path) -> dict[str, Any]:
    run = _lineage_root(root)
    recovered = lineage_state(run)
    current = recovered["current_branches"]
    plan_path = run / "DELEGATION_PLAN.json"
    state_path = run / "STATE.json"
    if current:
        first = current[0]
        plan = {
            "schema_version": 1, "lineage_schema_version": LINEAGE_SCHEMA_VERSION,
            "authoritative_source": LINEAGE_FILE,
            "lineage_id": first["lineage_id"], "race_id": first["race_id"],
            "generation": first["generation"], "run_id": run.name,
            "challenge_id": first.get("challenge_id"),
            "challenge_instance_id": first["lifecycle_history"][0]["challenge_instance_id"],
            "attempt_id": first["lifecycle_history"][0]["attempt_id"],
            "input_fingerprint": first.get("input_fingerprint"),
            "target_revision": first.get("target_revision"),
            "parent_session_id": first.get("parent_branch_id"), "mode": first["mode"],
            "tier": (first["lifecycle_history"][0].get("details") or {}).get("legacy_tier"),
            "tier_reason": (first["lifecycle_history"][0].get("details") or {}).get("tier_reason", ""),
            "created_at": min(str(row["created_at"]) for row in current),
            "updated_at": max(str(row["updated_at"]) for row in current),
            "planned_width": len(current), "active_width": sum(row["status"] == "RUNNING" for row in current),
            "branches": [_project_branch(row) for row in current],
            "legacy_board_view": bool(
                (first["lifecycle_history"][0].get("details") or {}).get("legacy_board_view")
            ),
            "projection": True,
        }
        _preserve_bad_projection(plan_path, expected=(dict,))
        atomic_json(plan_path, plan)
    if state_path.is_file():
        _preserve_bad_projection(state_path, expected=(dict,))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["branches"] = [
            {
                "id": row["branch_id"], "branch_id": row["branch_id"],
                "session_id": row["session_id"], "generation": row["generation"],
                "status": row["status"], "mode": row["mode"],
                "supersedes_branch_id": row["supersedes_branch_id"],
            }
            for row in recovered["branches"]
        ]
        state["solve_mode"] = current[0]["mode"] if current else state.get("solve_mode", "adaptive-race")
        state["planned_child_width"] = len(current)
        state["active_child_width"] = recovered["active_width"]
        state["race_lineage_source"] = LINEAGE_FILE
        state["updated_at"] = utc_now()
        atomic_json(state_path, state)
    return recovered


def record_start_failure(
    root: Path, *, branch_id: str, receipt: Mapping[str, Any], reason: str,
) -> dict[str, Any]:
    event = append_lineage_event(
        root, event="START_FAILED", branch_id=branch_id,
        referenced_receipt=receipt, details={"reason": reason, "receipt": dict(receipt)},
    )
    run = _lineage_root(root)
    state = lineage_state(run)
    branch = next(row for row in state["branches"] if row["branch_id"] == branch_id)
    if branch["mode"] == SolveMode.FIXED_RACE.value:
        path = run / "RUN_MANIFEST.json"
        if path.is_file():
            manifest = json.loads(path.read_text(encoding="utf-8"))
            outcome = manifest.setdefault("outcome", {})
            outcome.update({
                "environment_failure": True,
                "invalidation_reason": "FIXED_RACE_CHILD_START_FAILURE",
                "terminal_correctness": False,
            })
            atomic_json(path, manifest)
    return event


def _transition_allowed(history: Sequence[Mapping[str, Any]], row: Mapping[str, Any]) -> bool:
    before = str(history[-1]["event"]) if history else None
    event = str(row["event"])
    return event in _ALLOWED.get(before, set())


def _validate_semantics(
    history: Sequence[Mapping[str, Any]], row: Mapping[str, Any], all_rows: Sequence[Mapping[str, Any]],
    *, run: Path,
) -> None:
    event = str(row["event"])
    events = [str(item["event"]) for item in history]
    if event == "PLANNED" and row.get("supersedes_branch_id"):
        if SolveMode(str(row["mode"])) is not SolveMode.ADAPTIVE_RACE:
            raise LineageError("only adaptive-race may plan a replacement branch")
        prior_replacements = {
            str(item["lineage_branch_id"])
            for item in all_rows
            if item.get("event") == "PLANNED" and item.get("supersedes_branch_id")
        }
        if prior_replacements:
            raise LineageError("adaptive-race permits at most one replacement")
        details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
        if (
            details.get("replacement_request_receipt") is not True
            or details.get("replacement_trigger_kind") not in {"PLATEAU", "REFUTATION"}
            or not details.get("triggering_receipt_id")
        ):
            raise LineageError("replacement planning requires an exact plateau/refutation request receipt")
        if not _replacement_trigger_exists(
            run, branch_id=str(row["supersedes_branch_id"]),
            receipt_id=str(details["triggering_receipt_id"]),
            kind=str(details["replacement_trigger_kind"]),
        ):
            raise LineageError("replacement trigger does not resolve to authoritative plateau/refutation evidence")
        old = next((
            item for item in reversed(all_rows)
            if item.get("branch_id") == row.get("supersedes_branch_id")
        ), None)
        if old is None:
            raise LineageError("replacement supersedes no lineage branch")
        if str(old.get("hypothesis_family", "")).casefold() == str(row.get("hypothesis_family", "")).casefold():
            raise LineageError("replacement hypothesis family must be genuinely distinct")
    if event in {"NATIVE_STARTED", "NATIVE_STOP_RECORDED"} and not row.get("referenced_receipt_digest"):
        raise LineageError(f"{event} requires an exact referenced receipt digest")
    if event == "NATIVE_STARTED":
        first_details = history[0].get("details") if history else {}
        contract = (
            first_details.get("branch_contract")
            if isinstance(first_details, Mapping) else {}
        )
        routed = isinstance(contract, Mapping) and contract.get("routing_profile") in {
            "MECHANICAL", "BOUNDED_EXPERIMENT", "IMPLEMENTATION", "DEEP_SOLVER",
            "CONFIRMED_BOTTLENECK",
        }
        observation_status = (
            (row.get("details") or {}).get("runtime_observation_status")
            if isinstance(row.get("details"), Mapping) else None
        )
        if routed and observation_status == "OBSERVED" and not row.get("operation_id"):
            raise LineageError("observed routed NATIVE_STARTED requires a native start operation ID")
        if row.get("operation_id") and any(
            item.get("event") == "NATIVE_STARTED"
            and item.get("operation_id") == row.get("operation_id")
            and (
                item.get("lineage_branch_id") != row.get("lineage_branch_id")
                or item.get("referenced_receipt_digest") != row.get("referenced_receipt_digest")
            )
            for item in all_rows
        ):
            raise LineageError("native start operation ID has conflicting runtime identity")
    if event == "NATIVE_STARTED" and any(
        item.get("event") == "NATIVE_STARTED"
        and item.get("session_id") == row.get("session_id")
        and item.get("lineage_branch_id") != row.get("lineage_branch_id")
        for item in all_rows
    ):
        raise LineageError("one native session_id cannot start for multiple lineage branches")
    if event == "SUPERSEDED":
        started = any(value in STARTED_EVENTS for value in events)
        terminal_evidence = any(value in TERMINAL_EVIDENCE for value in events)
        not_started = bool((row.get("details") or {}).get("not_started"))
        if started and not terminal_evidence:
            raise LineageError("started branch cannot be superseded without exact stop or child terminal receipt")
        if not started and not not_started:
            raise LineageError("unstarted supersession requires an explicit not-started receipt")
    if event == "TERMINAL":
        if any(value in STARTED_EVENTS for value in events) and not any(
            value in TERMINAL_EVIDENCE for value in events
        ):
            raise LineageError("started branch cannot become TERMINAL without native stop or child terminal evidence")
        if "SANDBOX_READY" in events and "SANDBOX_CLEANED" not in events:
            raise LineageError("sandbox-ready branch cannot become TERMINAL before sandbox cleanup")
        if "CAPACITY_ADMITTED" in events and "RESOURCE_RELEASED" not in events:
            raise LineageError("capacity-admitted branch cannot become TERMINAL before resource release")
    if event == "CAPACITY_ADMITTED" and row.get("supersedes_branch_id"):
        old_id = str(row["supersedes_branch_id"])
        old_rows = [item for item in all_rows if item.get("branch_id") == old_id]
        if old_rows and old_rows[-1].get("event") == "RUNNING":
            mode = SolveMode(str(row["mode"]))
            running = {
                str(item["lineage_branch_id"])
                for item in all_rows if item.get("event") == "RUNNING"
            }
            stopped = {
                str(item["lineage_branch_id"])
                for item in all_rows if item.get("event") in {
                    "STOP_REQUESTED", "NATIVE_STOP_RECORDED", "CHILD_TERMINAL_RESULT_RECORDED",
                    "START_FAILED", "SUPERSEDED", "TERMINAL",
                }
            }
            active = len(running - stopped)
            if active >= maximum_child_width(mode):
                raise LineageError(
                    "replacement cannot be capacity-admitted while its superseded branch is still RUNNING at maximum width"
                )


def _replacement_trigger_exists(
    run: Path, *, branch_id: str, receipt_id: str, kind: str,
) -> bool:
    if kind == "REFUTATION":
        return any(
            row.get("receipt_id") == receipt_id
            and row.get("event_type") == "PRIMITIVE_REFUTED"
            and row.get("session_id") == branch_id
            for row in read_jsonl_strict(run / "milestone-receipts.jsonl", "milestone receipt ledger")
        )
    transitions = read_jsonl_strict(run / "RACE_TRANSITIONS.jsonl", "race transition ledger")
    if any(
        receipt_id in {str(row.get("transition_id") or ""), str(row.get("event_id") or "")}
        and (
            row.get("session_id") == branch_id
            or any(
                isinstance(item, Mapping) and item.get("session_id") == branch_id
                for item in row.get("replacement_requests", []) or []
            )
        )
        for row in transitions
    ):
        return True
    return any(
        row.get("action_id") == receipt_id
        and row.get("action_type") == "REPLACE_ATTACK_FAMILY"
        and row.get("session_id") == branch_id
        for row in read_jsonl_strict(run / "control-actions.jsonl", "control action ledger")
    )


def _validate_row(row: Mapping[str, Any], run: Path) -> None:
    required = {
        "schema_version", "lineage_event_id", "challenge_instance_id", "attempt_id", "run_id",
        "lineage_id", "race_id", "generation", "branch_id", "lineage_branch_id",
        "session_id", "parent_branch_id", "supersedes_branch_id", "hypothesis_family",
        "mode", "event", "created_at", "referenced_receipt_digest",
    }
    if row.get("schema_version") != LINEAGE_SCHEMA_VERSION or required.difference(row):
        raise LineageError("race lineage row is missing required identity")
    if row.get("run_id") != run.name:
        raise LineageError("race lineage row belongs to another run")
    if row.get("event") not in LIFECYCLE_EVENTS:
        raise LineageError("race lineage row has an unsupported event")
    digest = str(row.get("referenced_receipt_digest") or "")
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise LineageError("race lineage referenced receipt digest is invalid")
    try:
        SolveMode(str(row.get("mode")))
    except ValueError as exc:
        raise LineageError("race lineage row has an unsupported mode") from exc
    if not isinstance(row.get("generation"), int) or int(row["generation"]) < 1:
        raise LineageError("race lineage generation is invalid")


def _run_identity(run: Path) -> dict[str, Any]:
    state = json.loads((run / "STATE.json").read_text(encoding="utf-8"))
    manifest_path = run / "RUN_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {}
    identity = manifest.get("identity") if isinstance(manifest.get("identity"), dict) else {}
    attempt_id = state.get("attempt_id") or identity.get("attempt_id")
    instance = state.get("challenge_instance_id") or identity.get("challenge_instance_id")
    if not attempt_id or not instance:
        digest = hashlib.sha256(canonical_json({
            "challenge_id": state.get("challenge_id"),
            "input_fingerprint": state.get("input_fingerprint"),
            "target_revision": state.get("target_revision"),
        })).hexdigest()
        attempt_id = attempt_id or f"legacy-{digest[:24]}"
        instance = instance or f"ci-{digest[:32]}"
    return {
        "challenge_instance_id": instance,
        "attempt_id": attempt_id,
        "run_id": run.name,
        "challenge_id": state.get("challenge_id"),
        "input_fingerprint": state.get("input_fingerprint"),
        "target_revision": state.get("target_revision"),
    }


def _lineage_root(root: Path) -> Path:
    """Keep historical standalone test/admin roots usable without migration."""

    candidate = root.resolve(strict=False)
    if (
        (candidate / "STATE.json").is_file()
        and not (candidate / "ACTIVE_RUN.json").exists()
        and candidate.parent.name != "runs"
    ):
        return candidate
    return resolve_active_run(root)


def _event_details(history: Sequence[Mapping[str, Any]], event: str) -> dict[str, Any] | None:
    row = next((item for item in reversed(history) if item["event"] == event), None)
    return dict(row.get("details") or {}) if row else None


def _project_branch(row: Mapping[str, Any]) -> dict[str, Any]:
    excluded = {
        "lifecycle_history", "started", "native_started", "terminal_evidence_recorded",
        "sandbox_cleaned", "resource_released", "terminal", "lineage_branch_id",
    }
    projected = {key: value for key, value in row.items() if key not in excluded}
    projected.setdefault("evidence_contract", ["authoritative lineage receipt"])
    projected.setdefault("success_condition", "decisive experiment proves the branch primitive")
    projected.setdefault("kill_condition", "decisive experiment refutes the branch primitive")
    projected.setdefault("maximum_steps", 80)
    projected.setdefault("budget_seconds", 1800)
    projected.setdefault("requested_model_role", "solver")
    projected.setdefault("requested_reasoning", "high")
    projected.setdefault("observed_runtime_model", None)
    projected.setdefault("observed_reasoning", None)
    projected.setdefault("runtime_observation_status", None)
    projected.setdefault("runtime_observation_evidence", None)
    projected.setdefault("pinning_verified", False)
    projected.setdefault("admission", {"admitted": True, "reason": "authoritative lineage plan"})
    projected.setdefault("started_at", None)
    projected.setdefault("finished_at", None)
    if row.get("status") == "CHILD_TERMINAL_RESULT_RECORDED":
        projected["lifecycle_status"] = row["status"]
        terminal = row.get("terminal_result_receipt")
        projected["status"] = (
            str(terminal.get("result_status") or "TERMINAL")
            if isinstance(terminal, Mapping) else "TERMINAL"
        )
    start = row.get("start_receipt")
    if isinstance(start, Mapping):
        projected.update({
            "native_start_receipt": dict(start),
            "observed_runtime_model": start.get("observed_model"),
            "observed_reasoning": start.get("observed_reasoning"),
            "runtime_observation_status": start.get("runtime_observation_status"),
            "runtime_observation_evidence": start.get("runtime_observation_evidence"),
            "routing_classification": start.get("routing_classification"),
            "model_routing_matched": start.get("model_routing_matched", False),
            "reasoning_routing_matched": start.get("reasoning_routing_matched", False),
            "routing_matched": start.get("routing_matched", False),
            "fallback_used": start.get("fallback_used", False),
            "fallback_reason_observed": start.get("fallback_reason"),
            "pinning_verified": start.get("routing_classification") == "ROUTING_MATCHED",
        })
    projected["native_delegation_required"] = True
    projected["expected_start_receipt"] = True
    return projected


def _preserve_bad_projection(path: Path, *, expected: tuple[type, ...]) -> None:
    if not path.exists():
        return
    if path.is_symlink() or not path.is_file():
        raise LineageError(f"projection is unsafe: {path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        backup = path.with_name(f"{path.stem}.corrupt-{utc_now().replace(':', '')}{path.suffix}")
        backup.write_bytes(path.read_bytes())
        return
    if not isinstance(value, expected):
        backup = path.with_name(f"{path.stem}.corrupt-{utc_now().replace(':', '')}{path.suffix}")
        backup.write_bytes(path.read_bytes())
