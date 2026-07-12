"""Versioned semantic replanning rules with deterministic idempotency."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from typing import Any, Callable, Iterable, Mapping, Protocol


class RuleValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Predicate:
    field: str | None = None
    op: str | None = None
    value: Any = None
    event: str | None = None
    all: tuple["Predicate", ...] = ()
    any: tuple["Predicate", ...] = ()
    not_: "Predicate | None" = None


@dataclass(frozen=True, slots=True)
class RuleAction:
    type: str
    parameters: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ReplanRule:
    id: str
    priority: int
    when: Predicate
    actions: tuple[RuleAction, ...]
    cooldown_seconds: int = 0
    max_fires: int = 1
    schema_version: int = 1


@dataclass(frozen=True, slots=True)
class RuleExecution:
    rule_id: str
    matched: bool
    executed_actions: tuple[str, ...] = ()
    reason: str = ""
    before: Mapping[str, Any] = field(default_factory=dict)
    after: Mapping[str, Any] = field(default_factory=dict)


_OPS = {"eq", "ne", "gte", "gt", "lte", "lt", "in", "contains", "exists", "changed"}
_ACTIONS = {
    "cancel_current_contract", "cancel_contracts", "pause_contracts", "resume_contracts",
    "spawn_plan", "create_contract", "change_priority", "promote_artifact",
    "handoff_artifact", "change_model", "reallocate_budget", "escalate",
    "run_verification", "end_session",
}


class RuleParser:
    def parse(self, raw: str | Mapping[str, Any]) -> ReplanRule:
        if isinstance(raw, str):
            stripped = raw.strip()
            if not stripped.startswith("{"):
                return self._legacy(stripped)
            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise RuleValidationError(f"invalid rule JSON: {exc.msg}") from exc
        if not isinstance(raw, Mapping):
            raise RuleValidationError("rule must be an object")
        version = raw.get("schema_version", 1)
        if version != 1:
            raise RuleValidationError(f"unsupported rule schema version {version}")
        allowed = {"schema_version", "id", "priority", "when", "actions", "cooldown_seconds", "max_fires"}
        unknown = set(raw) - allowed
        if unknown:
            raise RuleValidationError(f"unknown rule fields: {', '.join(sorted(unknown))}")
        rule_id = raw.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise RuleValidationError("rule.id must be a non-empty string")
        priority = raw.get("priority", 50)
        if isinstance(priority, bool) or not isinstance(priority, int) or not 1 <= priority <= 100:
            raise RuleValidationError("rule.priority must be 1..100")
        actions_raw = raw.get("actions")
        if not isinstance(actions_raw, (list, tuple)) or not actions_raw:
            raise RuleValidationError("rule.actions must be a non-empty list")
        actions: list[RuleAction] = []
        for index, item in enumerate(actions_raw):
            if not isinstance(item, Mapping) or not isinstance(item.get("type"), str):
                raise RuleValidationError(f"rule.actions[{index}] must contain type")
            action_type = str(item["type"])
            if action_type not in _ACTIONS:
                raise RuleValidationError(f"unsupported action type: {action_type}")
            parameters = item.get("parameters")
            if isinstance(parameters, Mapping) and set(item) <= {"type", "parameters"}:
                actions.append(RuleAction(action_type, dict(parameters)))
            else:
                actions.append(RuleAction(action_type, {key: value for key, value in item.items() if key != "type"}))
        cooldown = raw.get("cooldown_seconds", 0)
        max_fires = raw.get("max_fires", 1)
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in (cooldown, max_fires)) or max_fires < 1:
            raise RuleValidationError("cooldown_seconds must be >=0 and max_fires >=1")
        return ReplanRule(rule_id.strip(), priority, self._predicate(raw.get("when"), "rule.when"),
                          tuple(actions), cooldown, max_fires, version)

    def parse_many(self, values: Iterable[str | Mapping[str, Any]]) -> tuple[ReplanRule, ...]:
        rules = tuple(self.parse(value) for value in values)
        if len({rule.id for rule in rules}) != len(rules):
            raise RuleValidationError("rule ids must be unique")
        return tuple(sorted(rules, key=lambda item: (-item.priority, item.id)))

    def _predicate(self, raw: Any, where: str) -> Predicate:
        if not isinstance(raw, Mapping):
            raise RuleValidationError(f"{where} must be an object")
        raw = {key: value for key, value in raw.items()
               if not (key in {"all", "any", "not", "not_"} and value in (None, (), []))}
        if "not_" in raw:
            raw["not"] = raw.pop("not_")
        combinators = [key for key in ("all", "any", "not") if key in raw]
        if combinators:
            if len(combinators) != 1 or len(raw) != 1:
                raise RuleValidationError(f"{where} must contain exactly one combinator")
            key = combinators[0]
            if key == "not":
                return Predicate(not_=self._predicate(raw[key], f"{where}.not"))
            children = raw[key]
            if not isinstance(children, list) or not children:
                raise RuleValidationError(f"{where}.{key} must be a non-empty list")
            parsed = tuple(self._predicate(item, f"{where}.{key}") for item in children)
            return Predicate(all=parsed) if key == "all" else Predicate(any=parsed)
        allowed = {"event", "field", "op", "value"}
        unknown = set(raw) - allowed
        if unknown:
            raise RuleValidationError(f"unknown predicate fields: {', '.join(sorted(unknown))}")
        field = raw.get("field")
        event = raw.get("event")
        op = raw.get("op", "eq")
        if event is None and (not isinstance(field, str) or not field):
            raise RuleValidationError(f"{where} requires event or field")
        if not isinstance(op, str) or op not in _OPS:
            raise RuleValidationError(f"{where}.op is unsupported")
        return Predicate(str(field) if field is not None else None, op, raw.get("value"),
                         str(event) if event is not None else None)

    @staticmethod
    def _legacy(value: str) -> ReplanRule:
        if not value:
            raise RuleValidationError("legacy condition cannot be empty")
        # Explicit compatibility: legacy prose becomes a conservative
        # no-progress rule and is visibly identifiable in audit events.
        normalized = "-".join(value.casefold().split())[:48]
        return ReplanRule(f"legacy-{normalized}", 10,
                          Predicate(field="no_progress_duration", op="gte", value=600),
                          (RuleAction("escalate", {"reason": value, "legacy": True}),),
                          cooldown_seconds=600, max_fires=1)


class RuleState(Protocol):
    def snapshot(self) -> Mapping[str, Any]: ...
    def apply(self, action: RuleAction, event: Mapping[str, Any]) -> str: ...


class ReplanEngine:
    """Evaluate every event immediately; scheduler callers invoke once per tick."""

    def __init__(self, rules: Iterable[ReplanRule], *, clock: Callable[[], datetime] | None = None) -> None:
        self.rules = tuple(sorted(rules, key=lambda item: (-item.priority, item.id)))
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._fires: dict[str, list[datetime]] = {}
        self._event_keys: set[tuple[str, str]] = set()

    def evaluate(self, event: Mapping[str, Any], state: RuleState) -> tuple[RuleExecution, ...]:
        event_id = str(event.get("id", ""))
        results: list[RuleExecution] = []
        now = self.clock()
        claimed_domains: dict[str, str] = {}
        for rule in self.rules:
            key = (rule.id, event_id)
            if event_id and key in self._event_keys:
                results.append(RuleExecution(rule.id, False, reason="idempotent duplicate event"))
                continue
            fires = self._fires.get(rule.id, [])
            if len(fires) >= rule.max_fires:
                results.append(RuleExecution(rule.id, False, reason="max_fires reached"))
                continue
            if fires and (now - fires[-1]).total_seconds() < rule.cooldown_seconds:
                results.append(RuleExecution(rule.id, False, reason="cooldown active"))
                continue
            context = {**state.snapshot(), **dict(event), "event": dict(event)}
            if not _matches(rule.when, context):
                results.append(RuleExecution(rule.id, False, reason="predicate false"))
                continue
            before = dict(state.snapshot())
            executed_values: list[str] = []
            for action in rule.actions:
                domain = _action_domain(action.type)
                owner = claimed_domains.get(domain)
                if owner is not None and owner != rule.id:
                    executed_values.append(f"conflict_skipped:{action.type}:winner={owner}")
                    continue
                claimed_domains[domain] = rule.id
                executed_values.append(state.apply(action, event))
            executed = tuple(executed_values)
            after = dict(state.snapshot())
            self._fires.setdefault(rule.id, []).append(now)
            if event_id:
                self._event_keys.add(key)
            results.append(RuleExecution(rule.id, True, executed, before=before, after=after))
        return tuple(results)


class LocalSchedulerRuleState:
    """Adapter that applies rule actions to this node's durable scheduler state."""

    def __init__(self, state: Any, challenge_id: str) -> None:
        self.state = state
        self.challenge_id = challenge_id
        self.session = state.get_challenge_session(challenge_id)
        self._last_actions: list[str] = []

    def snapshot(self) -> Mapping[str, Any]:
        tasks = self.state.list_contract_tasks(self.session.id) if self.session else ()
        return {
            "challenge_id": self.challenge_id,
            "contract_counts": {status: sum(item.status.value == status for item in tasks)
                                for status in ("PENDING", "RUNNING", "PAUSED", "SUCCEEDED", "FAILED", "CANCELLED")},
            "contracts": [{"id": item.id, "status": item.status.value, "strategy": item.tool_strategy,
                           "priority": item.priority, "role": item.role,
                           "assigned_attempt_id": item.assigned_attempt_id} for item in tasks],
            "actions": tuple(self._last_actions),
        }

    def apply(self, action: RuleAction, event: Mapping[str, Any]) -> str:
        from dataclasses import replace
        from ..models import ContractTask, ContractTaskStatus, SessionStatus, stable_id
        from .planners import TacticalContract, default_planner_registry

        if self.session is None:
            result = "no active challenge session"
        elif action.type in {"cancel_current_contract", "cancel_contracts"}:
            selector = action.parameters.get("selector", {})
            tags = set(selector.get("tags_any", ())) if isinstance(selector, Mapping) else set()
            current = event.get("contract_id")
            cancelled: list[str] = []
            for item in self.state.list_contract_tasks(self.session.id):
                if item.status not in {ContractTaskStatus.PENDING, ContractTaskStatus.RUNNING}:
                    continue
                haystack = {item.role, item.tool_strategy, item.branch, *item.objective.casefold().split()}
                if action.type == "cancel_current_contract" and current != item.id:
                    continue
                if tags and not tags.intersection(haystack):
                    continue
                self.state.mark_contract_task_outcome(item.id, status=ContractTaskStatus.CANCELLED,
                                                      result_summary=f"cancelled by semantic rule for event {event.get('id', '')}")
                cancelled.append(item.id)
            result = f"cancelled:{','.join(cancelled)}"
        elif action.type in {"spawn_plan", "create_contract"}:
            profile_raw = self.state.get_problem_profile(self.challenge_id) or {
                "category": "misc", "subtype": "unknown", "confidence": 0.0,
            }
            from .profiles import ProblemProfile
            profile = ProblemProfile(**{key: value for key, value in profile_raw.items()
                                       if key in ProblemProfile.__dataclass_fields__})
            tactical = default_planner_registry().plan(profile)
            planner_hint = str(action.parameters.get("planner", ""))
            selected = list(tactical.contracts)
            if "exploit" in planner_hint:
                active_dependencies = tuple(
                    item.id for item in self.state.list_contract_tasks(self.session.id)
                    if item.status is ContractTaskStatus.RUNNING
                    and item.tool_strategy in {"dynamic_analysis", "fast_recon"}
                )
                selected = [TacticalContract(
                    id="semantic:exploit_build", hypothesis="convert promoted primitive into exploit",
                    prerequisites=(), strategy="exploit_build", harness="exploit_build",
                    commands=("bootstrap:exploit_build",), input_artifacts=("promoted_primitive",),
                    output_artifacts=("exploit", "transcript"), success_signals=("flag_candidate",),
                    failure_signals=("retry_exhausted",), transition_conditions=("verification",),
                    depends_on=active_dependencies, timeout_sec=1200,
                )]
            elif "ssrf" in planner_hint:
                active_dependencies = tuple(
                    item.id for item in self.state.list_contract_tasks(self.session.id)
                    if item.status is ContractTaskStatus.RUNNING
                    and item.tool_strategy == "protocol_replay"
                )
                selected = [TacticalContract(
                    id="semantic:ssrf_followup", hypothesis="use promoted internal endpoint in the authorized origin",
                    prerequisites=(), strategy="protocol_replay", harness="protocol_replay",
                    commands=("consume endpoint.json from /work/handoff",),
                    input_artifacts=("endpoint.json",), output_artifacts=("request.json", "transcript.jsonl"),
                    success_signals=("flag_candidate",), failure_signals=("endpoint_rejected",),
                    transition_conditions=("verification",), depends_on=active_dependencies, timeout_sec=900,
                )]
            created: list[str] = []
            for contract in selected:
                task_id = stable_id(self.session.id, f"rule:{event.get('id','')}:{contract.id}", prefix="task_")
                if self.state.get_contract_task(task_id) is not None:
                    continue
                role = "recon" if contract.strategy == "fast_recon" else "exploit"
                self.state.upsert_contract_task(ContractTask(
                    id=task_id, session_id=self.session.id, challenge_id=self.challenge_id,
                    branch=f"rule:{contract.id}", role=role, objective=contract.hypothesis,
                    tool_strategy=contract.strategy, timeout_sec=contract.timeout_sec,
                    priority=int(action.parameters.get("priority", 90)),
                    success_criteria=contract.success_signals, deliverables=contract.output_artifacts,
                    depends_on=contract.depends_on,
                ))
                created.append(task_id)
            result = f"created:{','.join(created)}"
        elif action.type == "change_priority":
            changed: list[str] = []
            for item in self.state.list_contract_tasks(self.session.id):
                if item.status in {ContractTaskStatus.PENDING, ContractTaskStatus.RUNNING}:
                    self.state.upsert_contract_task(replace(item, priority=int(action.parameters.get("priority", item.priority))))
                    changed.append(item.id)
            result = f"priority_changed:{','.join(changed)}"
        elif action.type in {"promote_artifact", "handoff_artifact"}:
            artifact_type = str(action.parameters.get("artifact_type", ""))
            if not artifact_type:
                result = f"intent:{action.type}:missing_artifact_type"
            else:
                consumer = (str(action.parameters.get("consumer") or action.parameters.get("planner") or "rule-handoff")
                            if action.type == "handoff_artifact" else None)
                promoted = self.state.promote_tactical_artifacts(self.challenge_id, artifact_type, consumer=consumer)
                result = f"{action.type}:{','.join(promoted)}"
        elif action.type in {"pause_contracts", "resume_contracts"}:
            changed = []
            source = ({ContractTaskStatus.PENDING, ContractTaskStatus.RUNNING}
                      if action.type == "pause_contracts" else {ContractTaskStatus.PAUSED})
            destination = (ContractTaskStatus.PAUSED
                           if action.type == "pause_contracts" else ContractTaskStatus.PENDING)
            for item in self.state.list_contract_tasks(self.session.id):
                if item.status in source:
                    self.state.mark_contract_task_outcome(item.id, status=destination)
                    changed.append(item.id)
            result = f"{action.type}:{','.join(changed)}"
        elif action.type == "change_model":
            changed = []
            for item in self.state.list_contract_tasks(self.session.id):
                if item.status is ContractTaskStatus.PENDING:
                    self.state.upsert_contract_task(replace(
                        item, model_profile=str(action.parameters.get("model_profile", "luna_medium")),
                        reasoning_effort=str(action.parameters.get("reasoning_effort", "medium")),
                    ))
                    changed.append(item.id)
            result = f"model_changed:{','.join(changed)}"
        elif action.type == "reallocate_budget":
            changed = []
            timeout = int(action.parameters.get("timeout_sec", 900))
            timeout = max(60, min(3600, timeout))
            for item in self.state.list_contract_tasks(self.session.id):
                if item.status in {ContractTaskStatus.PENDING, ContractTaskStatus.RUNNING}:
                    self.state.upsert_contract_task(replace(item, timeout_sec=timeout))
                    changed.append(item.id)
            result = f"budget_reallocated:{','.join(changed)}"
        elif action.type == "escalate":
            changed = []
            for item in self.state.list_contract_tasks(self.session.id):
                if item.status is ContractTaskStatus.PENDING:
                    self.state.upsert_contract_task(replace(item, model_profile="sol_high", reasoning_effort="high"))
                    changed.append(item.id)
            result = f"escalated:{','.join(changed)}"
        elif action.type == "run_verification":
            task_id = stable_id(self.session.id, f"verify:{event.get('id','')}", prefix="task_")
            if self.state.get_contract_task(task_id) is None:
                self.state.upsert_contract_task(ContractTask(
                    id=task_id, session_id=self.session.id, challenge_id=self.challenge_id,
                    branch=f"verify:{event.get('id','')}", role="verification",
                    objective="independently replay and verify the promoted candidate",
                    prompt_family="verification", tool_strategy="independent_validation",
                    timeout_sec=300, priority=100,
                    success_criteria=("verification_proof",), deliverables=("proof.json",),
                ))
            result = f"verification_created:{task_id}"
        elif action.type == "end_session":
            self.state.checkpoint_challenge_session(self.challenge_id, status=SessionStatus.COMPLETED)
            result = "session_completed"
        else:
            # Unknown future actions cannot reach this branch because the
            # parser rejects them; retain an explicit intent for defense in depth.
            result = f"intent:{action.type}"
        self._last_actions.append(result)
        return result


def _resolve(context: Mapping[str, Any], path: str) -> Any:
    current: Any = context
    for part in path.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            return None
    return current


def _action_domain(action_type: str) -> str:
    if action_type in {"cancel_current_contract", "cancel_contracts", "pause_contracts", "resume_contracts"}:
        return "contract_lifecycle"
    if action_type in {"spawn_plan", "create_contract", "run_verification"}:
        return "contract_creation"
    if action_type in {"change_model", "reallocate_budget", "escalate"}:
        return "execution_policy"
    if action_type in {"promote_artifact", "handoff_artifact"}:
        return "artifact_state"
    return action_type


def _matches(predicate: Predicate, context: Mapping[str, Any]) -> bool:
    if predicate.all:
        return all(_matches(item, context) for item in predicate.all)
    if predicate.any:
        return any(_matches(item, context) for item in predicate.any)
    if predicate.not_ is not None:
        return not _matches(predicate.not_, context)
    if predicate.event is not None:
        event_type = _resolve(context, "event.type") or context.get("type")
        if event_type != predicate.event:
            return False
        if predicate.field is None:
            return True
    actual = _resolve(context, predicate.field or "")
    expected, op = predicate.value, predicate.op
    try:
        if op == "eq": return actual == expected
        if op == "ne": return actual != expected
        if op == "gte": return actual is not None and actual >= expected
        if op == "gt": return actual is not None and actual > expected
        if op == "lte": return actual is not None and actual <= expected
        if op == "lt": return actual is not None and actual < expected
        if op == "in": return actual in expected
        if op == "contains": return expected in actual
        if op == "exists": return (actual is not None) is bool(expected)
        if op == "changed": return actual != _resolve(context, f"previous.{predicate.field}")
    except (TypeError, ValueError):
        return False
    return False
