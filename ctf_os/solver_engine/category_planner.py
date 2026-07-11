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
    "id", "worker", "exclusive_scope", "objective", "first_decisive_action",
    "success_condition", "stop_condition", "handoff",
})


class PlanParseError(ValueError):
    """Raised when a planner response is not exactly the contract schema."""


def _required_string(record: dict[str, Any], key: str, where: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PlanParseError(f"{where}.{key} must be a non-empty string")
    return value.strip()


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
            values = {key: _required_string(item, key, where) for key in _CONTRACT_KEYS}
            if values["worker"] not in _WORKERS:
                raise PlanParseError(f"{where}.worker must be one of: {', '.join(sorted(_WORKERS))}")
            if values["id"] in ids:
                raise PlanParseError("contract ids must be unique")
            normalized_scope = " ".join(values["exclusive_scope"].lower().split())
            if normalized_scope in scopes:
                raise PlanParseError("contract exclusive_scope values must be distinct")
            ids.add(values["id"])
            scopes.add(normalized_scope)
            contracts.append(ExecutionContract(**values))

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
a runnable local exploit or solver. You own strategy; workers own execution.

Do not write a tutorial, tool inventory, broad category checklist, or a flag.
Do not ask workers to \"investigate generally\".
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

Choose workers: terra_high/terra_xhigh implement one concrete hypothesis;
luna_medium/luna_high answer one narrow branching question; sol_high/sol_xhigh
take a hard conceptual fork, a stalled branch, or contradictory outputs. Sol's
persistent session remains the owner and will consume every handoff and issue
the next contracts; a branch ending never ends the challenge session.

If and only if the rolling summary contains a replay-verified candidate and
you approve its evidence, set approved_candidate to that exact value.
Return exactly one JSON object with these exact keys and no others:
{{"solve_target":"...","representation":"state|protocol|validation|algebra|file-flow","mode":"direct|parallel|escalate","contracts":[{{"id":"A","worker":"terra_high|terra_xhigh|luna_medium|luna_high|sol_high|sol_xhigh","exclusive_scope":"...","objective":"...","first_decisive_action":"...","success_condition":"...","stop_condition":"...","handoff":"..."}}],"replan_when":"new decisive result|two contracts terminate|contradiction","escalate_when":"two distinct branches fail or conceptual ambiguity remains","approved_candidate":null}}"""
