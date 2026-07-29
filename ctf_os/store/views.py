"""Pure renderers for state-derived operator and model context views."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from ctf_os.models import ChallengeState


def _one_line(value: str) -> str:
    return " ".join(value.replace("\x00", "\N{REPLACEMENT CHARACTER}").split())


def board_entry(state: ChallengeState) -> dict[str, Any]:
    """Return a JSON-ready contest board row."""

    active_goal = state.active_goal
    allocated = state.budget.allocated_seconds
    return {
        "contest_id": state.contest_id,
        "category": state.category,
        "challenge_id": state.challenge_id,
        "challenge_key": state.identity.key,
        "status": state.status.value,
        "revision": state.revision,
        "active_goal": (
            {
                "id": active_goal.id,
                "description": active_goal.description,
                "status": active_goal.status.value,
            }
            if active_goal is not None
            else None
        ),
        "facts": len(state.facts),
        "open_hypotheses": sum(
            hypothesis.status.value in {"open", "supported"}
            for hypothesis in state.hypotheses
        ),
        "progress_markers": len(state.progress_markers),
        "candidates": [
            {"id": candidate.id, "status": candidate.status.value}
            for candidate in state.candidates
        ],
        "budget": {
            "allocated_seconds": allocated,
            "spent_seconds": state.budget.spent_seconds,
            "remaining_seconds": state.budget.remaining_seconds,
        },
        "updated_at": state.updated_at,
    }


def render_current_markdown(state: ChallengeState) -> str:
    """Render the bounded state summary used as the default context view."""

    lines = [
        f"# {state.contest_id} / {state.category} / {state.challenge_id}",
        "",
        f"- Status: `{state.status.value}`",
        f"- Revision: `{state.revision}`",
        f"- Updated: `{state.updated_at}`",
    ]
    if state.source_path:
        lines.append(f"- Source: `{_one_line(state.source_path)}`")
    lines.append("")

    if state.description or state.prompt:
        lines.extend(["## Challenge", ""])
        if state.description:
            lines.append(_one_line(state.description))
        if state.prompt:
            if state.description:
                lines.append("")
            lines.append(_one_line(state.prompt))
        lines.append("")

    lines.extend(["## Active goal", ""])
    goal = state.active_goal
    if goal is None:
        lines.append("_None._")
    else:
        lines.append(
            f"- `{goal.id}` [{goal.status.value}] "
            f"{_one_line(goal.description)}"
        )
        if goal.depends_on:
            lines.append("- Depends on: " + ", ".join(goal.depends_on))
    lines.append("")

    lines.extend(["## Confirmed observations", ""])
    if not state.facts:
        lines.append("_None yet._")
    else:
        for fact in state.facts[-50:]:
            pointers = []
            if fact.source_run_id:
                pointers.append(f"run `{fact.source_run_id}`")
            if fact.artifact_id:
                pointers.append(f"artifact `{fact.artifact_id}`")
            if fact.locator:
                pointers.append(f"`{_one_line(fact.locator)}`")
            suffix = f" — {'; '.join(pointers)}" if pointers else ""
            lines.append(
                f"- `{fact.id}` [{fact.provenance.value}] "
                f"{_one_line(fact.statement)}{suffix}"
            )
    lines.append("")

    lines.extend(["## Open hypotheses", ""])
    open_hypotheses = [
        item
        for item in state.hypotheses
        if item.status.value in {"open", "supported"}
    ]
    if not open_hypotheses:
        lines.append("_None._")
    else:
        for hypothesis in open_hypotheses[-30:]:
            lines.append(
                f"- `{hypothesis.id}` [{hypothesis.status.value}] "
                f"{_one_line(hypothesis.statement)}"
            )
            lines.append(
                "  - Falsifier: "
                + _one_line(hypothesis.falsifier.description)
            )
    lines.append("")

    lines.extend(["## Recent experiments", ""])
    if not state.experiments:
        lines.append("_None._")
    else:
        for experiment in state.experiments[-10:]:
            lines.append(
                f"- `{experiment.id}` [{experiment.status.value}] "
                f"`{_one_line(experiment.command)}`"
            )
            if experiment.result is not None:
                lines.append(
                    f"  - Result: {_one_line(str(experiment.result))}"
                )
    lines.append("")

    lines.extend(["## Progress markers", ""])
    if not state.progress_markers:
        lines.append("_None._")
    else:
        for marker in state.progress_markers[-30:]:
            pointer = f" (run `{marker.run_id}`)" if marker.run_id else ""
            lines.append(
                f"- `{marker.id}` {_one_line(marker.statement)}{pointer}"
            )
    lines.append("")

    remaining = state.budget.remaining_seconds
    lines.extend(
        [
            "## Budget",
            "",
            f"- Allocated seconds: `{state.budget.allocated_seconds}`",
            f"- Spent seconds: `{state.budget.spent_seconds}`",
            f"- Remaining seconds: `{remaining}`",
            "",
            "## Candidate flags",
            "",
        ]
    )
    if not state.candidates:
        lines.append("_None._")
    else:
        for candidate in state.candidates:
            source = (
                f" from run `{candidate.source_run_id}`"
                if candidate.source_run_id
                else ""
            )
            lines.append(
                f"- `{candidate.id}` [{candidate.status.value}]{source}: "
                f"`{_one_line(candidate.value)}`"
            )
    lines.append("")

    lines.extend(["## Artifact pointers", ""])
    if not state.artifacts:
        lines.append("_None._")
    else:
        for artifact in state.artifacts[-50:]:
            lines.append(
                f"- `{artifact.id}` `{_one_line(artifact.path)}` "
                f"`sha256:{artifact.sha256}`"
            )
    lines.append("")
    return "\n".join(lines)


def render_board_markdown(
    contest_id: str,
    entries: Iterable[Mapping[str, Any]],
) -> str:
    rows = sorted(
        entries,
        key=lambda entry: (
            str(entry.get("category", "")),
            str(entry.get("challenge_id", "")),
        ),
    )
    lines = [
        f"# {contest_id} board",
        "",
        "| Category | Challenge | Status | Revision | Active goal | Budget | Candidates |",
        "|---|---|---:|---:|---|---:|---:|",
    ]
    for entry in rows:
        active = entry.get("active_goal")
        active_text = (
            _one_line(str(active.get("description", "")))
            if isinstance(active, Mapping)
            else ""
        )
        budget = entry.get("budget", {})
        remaining = (
            budget.get("remaining_seconds")
            if isinstance(budget, Mapping)
            else None
        )
        candidates = entry.get("candidates", [])
        lines.append(
            "| "
            + " | ".join(
                [
                    _one_line(str(entry.get("category", ""))),
                    _one_line(str(entry.get("challenge_id", ""))),
                    f"`{entry.get('status', '')}`",
                    str(entry.get("revision", "")),
                    active_text,
                    str(remaining if remaining is not None else "∞"),
                    str(len(candidates) if isinstance(candidates, list) else 0),
                ]
            )
            + " |"
        )
    if not rows:
        lines.extend(["", "_No challenges yet._"])
    lines.append("")
    return "\n".join(lines)


# Compatibility-friendly concise names.
render_current = render_current_markdown
render_board = render_board_markdown


__all__ = [
    "board_entry",
    "render_board",
    "render_board_markdown",
    "render_current",
    "render_current_markdown",
]
