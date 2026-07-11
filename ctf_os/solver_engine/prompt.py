"""Render explicit, bounded child solver session prompts from a ChallengeContext."""

from __future__ import annotations

from dataclasses import dataclass

from .context import ChallengeContext
from .category_planner import CategoryPlanner
from .race_plan import RaceAttempt


@dataclass(frozen=True)
class SessionHandoff:
    """Coordinator-validated challenge state passed across isolated branches."""

    session_summary: str = ""
    validated_findings: tuple[str, ...] = ()
    replay_artifacts: tuple[str, ...] = ()
    branch_handoffs: tuple[str, ...] = ()

_SAFETY = """Safety invariants:
- This is an authorized CTF challenge only.
- Only inspect files under the challenge workspace.
- Only connect to remotes explicitly listed in contest.md below.
- Do not scan unrelated networks.
- Do not access credentials, SSH keys, browser data, API keys, or personal files.
- Do not modify host system configuration.
- Do not write outside /work and /artifacts.
- Original challenge files are mounted read-only at /workspace.
- /work and /artifacts are both private to this one attempt; they are never shared challenge output.
- Do not access or name sibling attempt workspaces, files, helpers, or tokens. Injected known findings are coordinator hints only: validate them independently before use.
- Run challenge commands through ctf-exec (for example: ctf-exec file /workspace/chall).
- Do not invent flags or print placeholder flags."""

_TAGS = "[PLAN] [HYPOTHESIS] [ACTION] [OBSERVATION] [FINDING] [FAIL] [SHIFT] [FLAG_CANDIDATE] [ARTIFACT] [TASK_DONE]"


def _items(values: tuple[str, ...]) -> str:
    return "\n".join(f"- {value}" for value in values) if values else "- (none)"


class PromptRenderer:
    def render(
        self, context: ChallengeContext, attempt: RaceAttempt, *, handoff: SessionHandoff | None = None,
    ) -> str:
        handoff = handoff or SessionHandoff()
        if attempt.branch_kind == "leader":
            return CategoryPlanner().render(
                context,
                session_id=attempt.session_id or "",
                session_summary=handoff.session_summary,
                findings=handoff.validated_findings or context.findings,
                failures=context.failed_strategies,
                contracts=handoff.branch_handoffs,
            )
        contract = ""
        if attempt.contract is not None:
            item = attempt.contract
            execution = item.execution
            assert execution is not None
            contract = f"""You own contract {item.id}. Solve the assigned branch; do not provide a narrative.

Objective: {item.objective}
Child solver session role: {item.session_role}
Exclusive scope: {item.exclusive_scope}
First decisive action: {item.first_decisive_action}
Stop condition: {item.stop_condition}
Success means: {item.success_condition}
Handoff required: {item.handoff}
Backend: {execution.backend}
Model profile: {execution.model_profile}
Reasoning effort: {execution.reasoning_effort}
Prompt family: {execution.prompt_family}
Timeout: {execution.timeout_sec} seconds
Tool strategy: {execution.tool_strategy}
Scheduler priority: {execution.priority}

Start executing. Every action must either test this branch or construct its solver.
If the stop condition is reached, emit the decisive negative result and exact handoff;
do not continue broad exploration.

"""
        return f"""{contract}You are a child CTF solver session. Work on this one contract only.

Challenge:
- id: {context.challenge_id}
- title: {context.title}
- category: {context.category}
- score: {context.score}
- description: {context.description or '(none)'}

Attempt:
- id: {attempt.attempt_id}
- profile: {attempt.profile.name}
- role: {attempt.profile.role}
- maximum runtime: {attempt.profile.max_runtime_sec} seconds
- strategy seed: {attempt.strategy_seed}
- profile instruction: {attempt.strategy_instruction}
- persistent session: {attempt.session_id or '(legacy one-shot)'}

Challenge files:
{_items(context.files)}

Remotes authorized by contest.md (and no others):
{_items(context.allowed_remotes)}

Coordinator hints from earlier observable challenge events (independently validate before use):
{_items(context.findings)}

Failed strategies; do not repeat without a new, recorded reason:
{_items(context.failed_strategies)}

Previously tried or failed commands; do not repeat without a new, recorded reason:
{_items(context.failed_commands)}

Supervisor/operator guidance from this same local challenge:
{_items(context.hints)}

Controller-validated session state (trusted as handoff, but replay before a flag decision):
- summary: {handoff.session_summary or '(none)'}
- validated findings:
{_items(handoff.validated_findings)}
- parent-approved replay artifacts:
{_items(handoff.replay_artifacts)}
- completed branch handoffs:
{_items(handoff.branch_handoffs)}

{_SAFETY}

Solve the assigned branch end to end; optimize for a valid flag, not for a report. Never wait for another child session. Execute the selected prompt family and tool strategy as a closed loop: run a discriminating command, inspect its actual output, update the attack, and continue through verification. Use scripts and debuggers instead of mental simulation when possible. Keep this attempt's tool path distinct from its profile peers. Stop repeating a path when it produces no new state, primitive, decoded bytes, or constraint.

Emit only concise machine-readable milestones using these tags: {_TAGS}
Do not emit private chain-of-thought. Record commands and decisive observations, not narration. Record a SHIFT when a branch stalls. A flag is only a candidate until independently verified.

Verification contract: if you emit [ARTIFACT] for a real replay/verify file, it must accept argv options --candidate, --challenge-id, --attempt-id, and --nonce. It may succeed only after reproducing the exact candidate, then print exactly one line in this form: [VERIFICATION_PROOF] {{"candidate":"...","challenge_id":"...","attempt_id":"...","nonce":"..."}}. Exit status 0 without that fresh proof is not verification."""
