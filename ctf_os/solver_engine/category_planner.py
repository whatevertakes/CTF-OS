"""Sol planning prompts and strict execution-contract parsing."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Iterable

from .context import ChallengeContext


_WORKERS = frozenset({"terra_high", "terra_xhigh", "luna_medium", "luna_high", "sol_high", "sol_xhigh"})
_MODES = frozenset({"direct", "parallel", "escalate"})
_REPRESENTATIONS = frozenset({"state", "protocol", "validation", "algebra", "file-flow"})
_TOP_KEYS = frozenset({
    "solve_target", "representation", "mode", "contracts", "replan_when", "escalate_when", "approved_candidate",
})
_REQUIRED_TOP_KEYS = _TOP_KEYS - {"approved_candidate"}
_CONTRACT_KEYS = frozenset({
    "id", "session_role", "exclusive_scope", "objective", "first_decisive_action",
    "success_condition", "stop_condition", "handoff", "execution",
})
_EXECUTION_KEYS = frozenset({
    "backend", "model_profile", "reasoning_effort", "prompt_family",
    "timeout_sec", "tool_strategy", "priority",
})
_PROFILE_EFFORT = {
    "sol_high": "high", "sol_xhigh": "max", "terra_high": "high",
    "terra_xhigh": "max", "luna_medium": "medium", "luna_high": "high",
}
_PROMPT_FAMILIES = frozenset({"recon", "implementation", "deep_solve", "takeover", "verification"})
_SESSION_ROLES = frozenset({"recon", "exploit", "reverse", "fuzz_symbolic", "verification", "takeover"})
_TOOL_STRATEGIES = frozenset({
    "fast_recon", "exploit_build", "deep_analysis", "symbolic_math",
    "dynamic_analysis", "protocol_replay", "artifact_recovery", "independent_validation",
})


class PlanParseError(ValueError):
    """Raised when a planner response is not exactly the contract schema."""


def _required_string(record: dict[str, Any], key: str, where: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PlanParseError(f"{where}.{key} must be a non-empty string")
    return value.strip()


@dataclass(frozen=True)
class BranchExecutionSpec:
    backend: str = "codex"
    model_profile: str = "terra_high"
    reasoning_effort: str = "high"
    prompt_family: str = "implementation"
    timeout_sec: int = 1200
    tool_strategy: str = "exploit_build"
    priority: int = 50


@dataclass(frozen=True)
class ExecutionContract:
    id: str
    worker: str
    exclusive_scope: str
    objective: str
    first_decisive_action: str
    success_condition: str
    stop_condition: str
    handoff: str
    session_role: str | None = None
    execution: BranchExecutionSpec | None = None

    def __post_init__(self) -> None:
        # Compatibility for controller-authored bootstrap contracts. Live Sol
        # JSON is still required by SolvePlanParser to provide every field.
        if self.session_role is None:
            object.__setattr__(self, "session_role", (
                "recon" if self.worker.startswith("luna_") else
                "takeover" if self.worker.startswith("sol_") else "exploit"
            ))
        if self.execution is None:
            family = "recon" if self.worker.startswith("luna_") else (
                "deep_solve" if self.worker.startswith("sol_") else "implementation"
            )
            strategy = "fast_recon" if family == "recon" else (
                "deep_analysis" if family == "deep_solve" else "exploit_build"
            )
            timeout = 600 if self.worker == "luna_medium" else 900 if self.worker == "luna_high" else (
                1800 if self.worker.endswith("xhigh") else 1500 if self.worker.startswith("sol_") else 1200
            )
            object.__setattr__(self, "execution", BranchExecutionSpec(
                model_profile=self.worker,
                reasoning_effort=_PROFILE_EFFORT.get(self.worker, "high"),
                prompt_family=family, timeout_sec=timeout, tool_strategy=strategy,
            ))


@dataclass(frozen=True)
class SolvePlan:
    solve_target: str
    representation: str
    mode: str
    contracts: tuple[ExecutionContract, ...]
    replan_when: str
    escalate_when: str
    approved_candidate: str | None = None


class SolvePlanParser:
    """Accept one JSON object only; reject prose, coercions and unknown fields."""

    def parse(self, output: str) -> SolvePlan:
        try:
            raw = json.loads(output)
        except json.JSONDecodeError as exc:
            raise PlanParseError(f"planner output must be exactly one JSON object: {exc.msg}") from exc
        if not isinstance(raw, dict):
            raise PlanParseError("planner output must be a JSON object")
        unknown = set(raw) - _TOP_KEYS
        missing = _REQUIRED_TOP_KEYS - set(raw)
        if unknown or missing:
            raise PlanParseError(self._shape_error("plan", missing, unknown))

        representation = _required_string(raw, "representation", "plan")
        if representation not in _REPRESENTATIONS:
            raise PlanParseError(f"plan.representation must be one of: {', '.join(sorted(_REPRESENTATIONS))}")
        mode = _required_string(raw, "mode", "plan")
        if mode not in _MODES:
            raise PlanParseError(f"plan.mode must be one of: {', '.join(sorted(_MODES))}")
        contracts_raw = raw["contracts"]
        if not isinstance(contracts_raw, list) or not 1 <= len(contracts_raw) <= 4:
            raise PlanParseError("plan.contracts must contain 1 to 4 contracts")

        contracts: list[ExecutionContract] = []
        ids: set[str] = set()
        scopes: set[str] = set()
        for index, item in enumerate(contracts_raw):
            where = f"plan.contracts[{index}]"
            if not isinstance(item, dict):
                raise PlanParseError(f"{where} must be an object")
            unknown = set(item) - _CONTRACT_KEYS
            missing = _CONTRACT_KEYS - set(item)
            if unknown or missing:
                raise PlanParseError(self._shape_error(where, missing, unknown))
            values = {key: _required_string(item, key, where) for key in _CONTRACT_KEYS - {"execution"}}
            if values["session_role"] not in _SESSION_ROLES:
                raise PlanParseError(f"{where}.session_role must be one of: {', '.join(sorted(_SESSION_ROLES))}")
            if values["id"] in ids:
                raise PlanParseError("contract ids must be unique")
            normalized_scope = " ".join(values["exclusive_scope"].lower().split())
            if normalized_scope in scopes:
                raise PlanParseError("contract exclusive_scope values must be distinct")
            ids.add(values["id"])
            scopes.add(normalized_scope)
            execution = self._parse_execution(item["execution"], where)
            contracts.append(ExecutionContract(
                **values, worker=execution.model_profile, execution=execution,
            ))

        if mode == "direct" and len(contracts) != 1:
            raise PlanParseError("direct mode requires exactly one contract")
        if mode == "parallel" and len(contracts) < 2:
            raise PlanParseError("parallel mode requires at least two contracts")
        return SolvePlan(
            solve_target=_required_string(raw, "solve_target", "plan"),
            representation=representation,
            mode=mode,
            contracts=tuple(contracts),
            replan_when=_required_string(raw, "replan_when", "plan"),
            escalate_when=_required_string(raw, "escalate_when", "plan"),
            approved_candidate=(str(raw["approved_candidate"]).strip()
                                if raw.get("approved_candidate") is not None else None),
        )

    @staticmethod
    def _parse_execution(raw: Any, where: str) -> BranchExecutionSpec:
        execution_where = f"{where}.execution"
        if not isinstance(raw, dict):
            raise PlanParseError(f"{execution_where} must be an object")
        unknown = set(raw) - _EXECUTION_KEYS
        missing = _EXECUTION_KEYS - set(raw)
        if unknown or missing:
            raise PlanParseError(SolvePlanParser._shape_error(execution_where, missing, unknown))
        backend = _required_string(raw, "backend", execution_where)
        profile = _required_string(raw, "model_profile", execution_where)
        effort = _required_string(raw, "reasoning_effort", execution_where)
        family = _required_string(raw, "prompt_family", execution_where)
        strategy = _required_string(raw, "tool_strategy", execution_where)
        timeout = raw.get("timeout_sec")
        priority = raw.get("priority")
        if backend != "codex":
            raise PlanParseError(f"{execution_where}.backend must be codex")
        if profile not in _PROFILE_EFFORT:
            raise PlanParseError(f"{execution_where}.model_profile is not an allowed CTF solver profile")
        if effort != _PROFILE_EFFORT[profile]:
            raise PlanParseError(f"{execution_where}.reasoning_effort does not match model_profile")
        if family not in _PROMPT_FAMILIES:
            raise PlanParseError(f"{execution_where}.prompt_family is not allowed")
        if strategy not in _TOOL_STRATEGIES:
            raise PlanParseError(f"{execution_where}.tool_strategy is not allowed")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 60 <= timeout <= 3600:
            raise PlanParseError(f"{execution_where}.timeout_sec must be an integer from 60 to 3600")
        if isinstance(priority, bool) or not isinstance(priority, int) or not 1 <= priority <= 100:
            raise PlanParseError(f"{execution_where}.priority must be an integer from 1 to 100")
        return BranchExecutionSpec(backend, profile, effort, family, timeout, strategy, priority)

    @staticmethod
    def _shape_error(where: str, missing: set[str], unknown: set[str]) -> str:
        parts = []
        if missing:
            parts.append("missing " + ", ".join(sorted(missing)))
        if unknown:
            parts.append("unknown " + ", ".join(sorted(unknown)))
        return f"{where} has " + "; ".join(parts)


class CategoryPlanner:
    """Render the same bounded Sol prompt for initial planning and replanning."""

    def render(
        self,
        context: ChallengeContext,
        *,
        session_id: str = "",
        session_summary: str = "",
        findings: Iterable[str] = (),
        failures: Iterable[str] = (),
        contracts: Iterable[str] = (),
    ) -> str:
        return _PLANNER_PROMPT.format(
            title=context.title,
            category=context.category,
            description=context.description or "(none)",
            files=json.dumps(list(context.files), ensure_ascii=False),
            remotes=json.dumps(list(context.allowed_remotes), ensure_ascii=False),
            session_id=session_id or "(new)",
            session_summary=session_summary or "(none)",
            findings=json.dumps(list(findings), ensure_ascii=False),
            failures=json.dumps(list(failures), ensure_ascii=False),
            contracts=json.dumps(list(contracts), ensure_ascii=False),
        )


_PLANNER_PROMPT = """You are Sol, the local solve orchestrator for one authorized CTF challenge.

Your only objective is to obtain a real, reproducible flag candidate through
a runnable local exploit or solver. You own strategy; child solver sessions execute it.

Do not write a tutorial, tool inventory, broad category checklist, or a flag.
Do not ask child sessions to \"investigate generally\".
Use the supplied category only to choose the representation that must be
broken: program state, protocol state, validation logic, algebraic relation,
file transformation chain, or application data flow.

<challenge>
title: {title}
category: {category}
description: {description}
files: {files}
authorized_remotes: {remotes}
</challenge>

<current_state>
session_id: {session_id}
rolling_session_summary: {session_summary}
decisive_observations: {findings}
discarded_branches: {failures}
active_or_completed_contracts: {contracts}
</current_state>

Create at most 4 independent execution contracts. A contract must have a
different uncertainty or attack surface from every other contract.

Prefer one direct executor when the likely route is clear. Use parallel work
only when its answers can change the next solve decision. A useful result is a
runnable artifact, a branch-selecting fact, or a conclusive negative result.

Create child solver sessions, not native subagents. session_role describes the
job (recon, exploit, reverse, fuzz_symbolic, verification, takeover), while
execution.model_profile independently selects Luna, Terra, or Sol. Sol's
persistent session remains the owner and consumes every handoff before issuing
the next child sessions; a child ending never ends the challenge session.

For every contract explicitly choose its complete execution profile. backend
is currently codex only. model_profile/reasoning_effort pairs are:
sol_high/high, sol_xhigh/max, terra_high/high, terra_xhigh/max,
luna_medium/medium, luna_high/high. Choose
prompt_family from recon, implementation, deep_solve, takeover, verification.
Choose tool_strategy from fast_recon, exploit_build, deep_analysis,
symbolic_math, dynamic_analysis, protocol_replay, artifact_recovery,
independent_validation. timeout_sec is 60..3600. priority is 1..100 and higher
priority branches are scheduled first.

For a clear easy route prefer one short direct session. For difficult or
uncertain challenges concentrate high/max profiles on the core path and use
parallel sessions only for genuinely disjoint attack surfaces or decisive
branch questions.

If and only if the rolling summary contains a replay-verified candidate and
you approve its evidence, set approved_candidate to that exact value.
Return exactly one JSON object with these exact keys and no others:
{{"solve_target":"...","representation":"state|protocol|validation|algebra|file-flow","mode":"direct|parallel|escalate","contracts":[{{"id":"A","session_role":"exploit|recon|reverse|fuzz_symbolic|verification|takeover","exclusive_scope":"...","objective":"...","first_decisive_action":"...","success_condition":"...","stop_condition":"...","handoff":"...","execution":{{"backend":"codex","model_profile":"terra_high","reasoning_effort":"high","prompt_family":"implementation","timeout_sec":1200,"tool_strategy":"exploit_build","priority":80}}}}],"replan_when":"new decisive result|two contracts terminate|contradiction","escalate_when":"two distinct branches fail or conceptual ambiguity remains","approved_candidate":null}}"""
