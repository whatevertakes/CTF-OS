"""Competition-first race planning for Sol-native delegation.

Python records a deterministic race and emits prompt packets.  It never starts,
stops, or supervises a model session; Sol owns the native delegation lifecycle.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any

from .delegation import (
    BranchCandidate, DelegationError, admit_branch, load_templates, plan_path, utc_now,
)
from .workspace import atomic_json, atomic_text, state_lock


RACE_SCHEMA_VERSION = 1
DEFAULT_WIDTH = {0: 0, 1: 2, 2: 3, 3: 4, 4: 4}


@dataclass(frozen=True, slots=True)
class RaceBranchSpec:
    session_id: str
    role: str
    hypothesis_family: str
    hypothesis: str
    scope: tuple[str, ...]
    tool_strategy: tuple[str, ...]
    expected_artifacts: tuple[str, ...]
    evidence_contract: tuple[str, ...]
    success_condition: str
    kill_condition: str
    maximum_steps: int = 80
    budget_seconds: int = 1800
    requested_model_role: str = "solver"
    requested_reasoning: str = "high"
    purpose: str = "parallel-race"
    race_override_reason: str | None = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any], *, index: int) -> "RaceBranchSpec":
        candidate = BranchCandidate.create(
            session_id=str(raw.get("session_id") or f"race-{index + 1}"),
            role=str(raw.get("role") or "independent-full-solve"),
            hypothesis_family=str(raw.get("hypothesis_family") or "independent-full-solve"),
            hypothesis=str(raw.get("hypothesis") or "Independently solve the challenge end to end"),
            scope=_strings(raw.get("scope") or ["challenge"]),
            tool_strategy=_strings(raw.get("tool_strategy") or ["independent-analysis", "solver-implementation"]),
            expected_artifacts=_strings(raw.get("expected_artifacts") or [f"artifacts/solver-{index + 1}"]),
        )
        evidence = tuple(_strings(raw.get("evidence_contract") or [
            "Publish confirmed facts and rejected hypotheses as race events",
            "Preserve exact commands and artifact paths",
            "Publish a remote flag immediately with its network receipt",
        ]))
        steps = int(raw.get("maximum_steps", 80))
        budget = int(raw.get("budget_seconds", 1800))
        if not 1 <= steps <= 10000 or not 1 <= budget <= 86400:
            raise DelegationError("race branch steps or budget are outside supported bounds")
        return cls(
            session_id=candidate.session_id, role=candidate.role,
            hypothesis_family=candidate.hypothesis_family, hypothesis=candidate.hypothesis,
            scope=candidate.scope, tool_strategy=candidate.tool_strategy,
            expected_artifacts=candidate.expected_artifacts, evidence_contract=evidence,
            success_condition=str(raw.get("success_condition") or "Obtain a flag or a reusable exploit/solver primitive"),
            kill_condition=str(raw.get("kill_condition") or "Exact scope violation, dead branch classification, or replacement by Sol"),
            maximum_steps=steps, budget_seconds=budget,
            requested_model_role=str(raw.get("requested_model_role") or raw.get("model_role") or "solver"),
            requested_reasoning=str(raw.get("requested_reasoning") or raw.get("reasoning") or "high"),
            purpose=str(raw.get("purpose") or "parallel-race"),
            race_override_reason=(str(raw["race_override_reason"]) if raw.get("race_override_reason") else None),
        )

    @property
    def candidate(self) -> BranchCandidate:
        return BranchCandidate.create(
            session_id=self.session_id, role=self.role,
            hypothesis_family=self.hypothesis_family, hypothesis=self.hypothesis,
            scope=self.scope, tool_strategy=self.tool_strategy,
            expected_artifacts=self.expected_artifacts,
        )


def parse_branch_spec(value: str | None, *, category: str, tier: int, template_path: Path) -> list[RaceBranchSpec]:
    if value:
        path = Path(value)
        if path.exists():
            if path.is_symlink() or not path.is_file():
                raise DelegationError("branch spec file is missing or unsafe")
            raw_text = path.read_text(encoding="utf-8")
        else:
            raw_text = value
        try:
            raw = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise DelegationError("--branch-spec must be a JSON array/object or a JSON file") from exc
        rows = raw.get("branches") if isinstance(raw, Mapping) else raw
        if not isinstance(rows, list):
            raise DelegationError("branch spec must contain a branches array")
        specs = [RaceBranchSpec.from_mapping(row, index=index) for index, row in enumerate(rows) if isinstance(row, Mapping)]
        if len(specs) != len(rows):
            raise DelegationError("every branch spec entry must be an object")
        return specs
    if tier == 0:
        return []
    templates = load_templates(template_path)
    selected = category if category in templates else "misc"
    rows = templates[selected][f"tier_{tier}"]
    width = DEFAULT_WIDTH[tier]
    if len(rows) < width:
        raise DelegationError(f"race template {selected}.tier_{tier} has fewer than {width} branches")
    return [_template_spec(row, index=index, category=selected) for index, row in enumerate(rows[:width])]


def start_race_plan(
    solve_root: Path, *, challenge_id: str, input_fingerprint: str,
    parent_session_id: str, category: str, tier: int, tier_reason: str,
    branch_specs: Sequence[RaceBranchSpec], threshold: float = .95,
) -> dict[str, Any]:
    if tier not in range(0, 5):
        raise DelegationError("tier must be an integer from 0 through 4")
    state_file = solve_root / "STATE.json"
    if state_file.is_symlink() or not state_file.is_file():
        raise DelegationError("challenge STATE.json is missing or unsafe")
    try:
        current_state = json.loads(state_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DelegationError("challenge STATE.json is malformed") from exc
    if (
        current_state.get("challenge_id") != challenge_id
        or current_state.get("input_fingerprint") != input_fingerprint
    ):
        raise DelegationError("race plan challenge identity or input fingerprint mismatch")
    if tier in {1, 2, 3} and len(branch_specs) < DEFAULT_WIDTH[tier]:
        raise DelegationError(f"tier {tier} race requires at least {DEFAULT_WIDTH[tier]} child branches")
    request_id = os.urandom(12).hex()
    _append_ledger(solve_root, {
        "event": "RACE_PLAN_REQUESTED", "request_id": request_id,
        "challenge_id": challenge_id, "input_fingerprint": input_fingerprint,
        "tier": tier, "branch_count": len(branch_specs), "created_at": utc_now(),
    })
    now = utc_now()
    plan: dict[str, Any] = {
        "schema_version": 1, "race_schema_version": RACE_SCHEMA_VERSION,
        "race_id": request_id, "challenge_id": challenge_id,
        "input_fingerprint": input_fingerprint, "parent_session_id": parent_session_id,
        "tier": tier, "tier_reason": tier_reason, "race_mode": "competition-first",
        "sol_lane": {
            "session_id": parent_session_id, "role": "lead-attacker-and-race-coordinator",
            "required": True, "status": "RUNNING",
            "instruction": "Pursue the highest-value deep solve path while coordinating the race.",
        },
        "created_at": now, "updated_at": now, "branches": [],
        "admission_decisions": [], "ledger_recoverable": True,
    }
    rejected: list[dict[str, Any]] = []
    for spec in branch_specs:
        decision = admit_branch(
            plan, spec.candidate, threshold=threshold, purpose=spec.purpose,
            race_override_reason=spec.race_override_reason,
        )
        plan["admission_decisions"].append({
            "session_id": spec.session_id, "candidate": _candidate_payload(spec.candidate),
            "purpose": spec.purpose, "race_override_reason": spec.race_override_reason,
            "evaluated_at": utc_now(), "result": decision,
        })
        if not decision["admitted"]:
            rejected.append({"session_id": spec.session_id, "reason": decision["reason"]})
            continue
        plan["branches"].append(_branch_payload(spec, decision, challenge_id, input_fingerprint, parent_session_id))
    with state_lock(solve_root):
        current = plan_path(solve_root)
        if current.is_symlink():
            raise DelegationError("delegation plan must not be a symlink")
        if current.is_file():
            raw_plan = current.read_text(encoding="utf-8", errors="replace")
            try:
                old = json.loads(raw_plan)
            except json.JSONDecodeError:
                atomic_text(solve_root / f"DELEGATION_PLAN.corrupt-{request_id[:8]}.txt", raw_plan)
                _append_ledger(solve_root, {
                    "event": "CORRUPT_PLAN_RECOVERED", "request_id": request_id,
                    "created_at": utc_now(),
                })
            else:
                for branch in old.get("branches", []):
                    if isinstance(branch, dict):
                        branch["status"] = "STALE"
                old["status"] = "STALE"
                old["superseded_at"] = utc_now()
                old["superseded_by_race_id"] = request_id
                archive = solve_root / f"DELEGATION_PLAN.stale-{str(old.get('race_id') or old.get('input_fingerprint') or 'legacy')[:16]}-{request_id[:8]}.json"
                atomic_json(archive, old)
        atomic_json(current, plan)
    _append_ledger(solve_root, {
        "event": "RACE_PLAN_COMMITTED", "request_id": request_id,
        "admitted": [row["session_id"] for row in plan["branches"]],
        "rejected": rejected, "created_at": utc_now(),
    })
    return race_board(plan, rejected=rejected)


def race_board(
    plan: Mapping[str, Any], *, rejected: Sequence[Mapping[str, Any]] = (),
    state: Mapping[str, Any] | None = None, events: Sequence[Mapping[str, Any]] = (),
    resources: Mapping[str, Any] | None = None, service_status: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    branches = []
    for branch in plan.get("branches", []):
        branch_events = [row for row in events if row.get("session_id") == branch.get("session_id")]
        latest = branch_events[-1] if branch_events else None
        branches.append({
            "session_id": branch.get("session_id"), "status": branch.get("status"),
            "role": branch.get("role"), "hypothesis_family": branch.get("hypothesis_family"),
            "requested_model_role": branch.get("requested_model_role"),
            "requested_reasoning": branch.get("requested_reasoning"),
            "observed_runtime_model": branch.get("observed_runtime_model"),
            "observed_reasoning": branch.get("observed_reasoning"),
            "current_utility_classification": branch.get("utility_classification", "INSUFFICIENT_DATA"),
            "last_checkpoint": latest,
            "last_new_evidence_time": latest.get("created_at") if latest else None,
            "artifacts": sorted({item for row in branch_events for item in row.get("artifacts", [])}),
            "prompt_packet": branch.get("prompt_packet"),
        })
    return {
        "challenge_id": plan.get("challenge_id"), "tier": plan.get("tier"),
        "race_id": plan.get("race_id"), "race_start_time": plan.get("created_at"),
        "mode": "competition-first", "sol_lane": plan.get("sol_lane"),
        "active_branches": branches, "rejected_exact_duplicates": list(rejected),
        "flag_candidate": state.get("flag_candidate") if state else None,
        "remote_flag": state.get("remote_flag") if state else None,
        "submission_recommendation": state.get("submission_recommended", False) if state else False,
        "service_status": dict(service_status or {"state": "UNKNOWN"}),
        "resource_use": dict(resources or {}),
        "native_children_created": False,
        "next_action": "Sol must immediately create admitted children with native runtime delegation using each prompt_packet.",
    }


def _template_spec(row: Mapping[str, Any], *, index: int, category: str) -> RaceBranchSpec:
    role = str(row["role"])
    family = str(row["hypothesis_family"])
    tools = _default_tools(category, role)
    return RaceBranchSpec.from_mapping({
        "session_id": f"race-{index + 1}-{role}", "role": role,
        "hypothesis_family": family,
        "hypothesis": f"Pursue {family} as an independent first-to-flag path",
        "scope": ["challenge-input", "declared-targets"], "tool_strategy": tools,
        "expected_artifacts": [f"artifacts/{role}-solver", f"evidence/{role}-receipts.jsonl"],
        "requested_model_role": "recon" if index == 0 else "implementation" if index == 1 else "deep-solver",
        "requested_reasoning": "high", "purpose": "independent-full-solve" if "independent" in role else "parallel-race",
    }, index=index)


def _default_tools(category: str, role: str) -> list[str]:
    tools = {
        "pwn": ["checksec", "gdb", "pwntools"], "rev": ["ghidra-or-objdump", "gdb", "z3-or-angr"],
        "web": ["source-dataflow", "http-client", "runtime-probing"],
        "crypto": ["python", "sage-or-z3", "known-answer-tests"],
        "forensic": ["file", "binwalk", "sleuthkit-or-tshark"],
        "osint": ["public-search", "archive", "metadata"],
        "cloud": ["provider-cli", "iam-graph", "scoped-mutation-ledger"],
        "ai": ["model-inspection", "pytorch", "differential-inference"],
        "misc": ["protocol-recon", "python-automation", "independent-solver"],
    }.get(category, ["static-analysis", "dynamic-analysis", "solver-implementation"])
    return tools + [role]


def _branch_payload(
    spec: RaceBranchSpec, admission: Mapping[str, Any], challenge_id: str,
    fingerprint: str, parent_session_id: str,
) -> dict[str, Any]:
    now = utc_now()
    packet = {
        "schema_version": 1, "session_id": spec.session_id,
        "parent_session_id": parent_session_id, "challenge_id": challenge_id,
        "input_fingerprint": fingerprint, "role": spec.role,
        "hypothesis_family": spec.hypothesis_family, "hypothesis": spec.hypothesis,
        "scope": list(spec.scope), "tool_strategy": list(spec.tool_strategy),
        "expected_artifacts": list(spec.expected_artifacts),
        "evidence_contract": list(spec.evidence_contract),
        "success_condition": spec.success_condition, "kill_condition": spec.kill_condition,
        "budget_seconds": spec.budget_seconds, "maximum_steps": spec.maximum_steps,
        "instruction": (
            "Solve independently and race for the first flag. Publish compact confirmed insights during long work. "
            "Use only this challenge and declared targets. Immediately publish REMOTE_FLAG_OBTAINED with receipt and artifact."
        ),
    }
    return {
        **_candidate_payload(spec.candidate), "evidence_contract": list(spec.evidence_contract),
        "success_condition": spec.success_condition, "kill_condition": spec.kill_condition,
        "maximum_steps": spec.maximum_steps, "budget_seconds": spec.budget_seconds,
        "requested_model_role": spec.requested_model_role,
        "requested_reasoning": spec.requested_reasoning,
        "observed_runtime_model": None, "observed_reasoning": None,
        "runtime_observation_evidence": None, "pinning_verified": False,
        "independent_verification": spec.purpose in {"independent-verification", "clean-room-verification"},
        "purpose": spec.purpose, "admission": dict(admission), "status": "ADMITTED",
        "prompt_packet": packet, "created_at": now, "started_at": None, "finished_at": None,
    }


def _candidate_payload(candidate: BranchCandidate) -> dict[str, Any]:
    return {
        "session_id": candidate.session_id, "role": candidate.role,
        "hypothesis_family": candidate.hypothesis_family, "hypothesis": candidate.hypothesis,
        "scope": list(candidate.scope), "tool_strategy": list(candidate.tool_strategy),
        "expected_artifacts": list(candidate.expected_artifacts),
    }


def _append_ledger(root: Path, payload: Mapping[str, Any]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    path = root / "RACE_LEDGER.jsonl"
    if path.is_symlink():
        raise DelegationError("race ledger must not be a symlink")
    line = json.dumps(dict(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    descriptor = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray)):
        raise DelegationError("race branch list field must be an array of strings")
    rows = [str(item).strip() for item in value]
    if not rows or any(not row for row in rows):
        raise DelegationError("race branch list field must contain non-empty strings")
    return rows
