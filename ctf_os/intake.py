"""Legacy/admin contest-wide Intake.

Solve preparation does not import or consume this module. Intake remains an
explicit whole-contest administration command and uses separate admin storage
so it cannot mutate a challenge Solve workspace.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .contest import discover_contests, select_contest
from .preflight import inspect_challenge_for_admin
from .problems import sync_contest_manifest
from .triage import invalidate_triage_outputs
from .workspace import atomic_json, atomic_text


def run_intake(
    repo: str | Path,
    contest_selector: str | None = None,
    *,
    force_challenge_ids: set[str] | frozenset[str] | None = None,
) -> dict[str, object]:
    """Run the explicitly requested legacy/admin whole-contest inventory."""

    root = Path(repo).resolve()
    sync_contest_manifest(root, contest_selector)
    manifest = select_contest(discover_contests(root / "incoming"), contest_selector)
    forced = force_challenge_ids or frozenset()
    records = [
        inspect_challenge_for_admin(
            root, manifest, challenge, force_materialize=challenge.id in forced,
        )
        for challenge in manifest.challenges
    ]
    payload: dict[str, object] = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "contest": manifest.to_dict(),
        "challenges": records,
        "summary": {
            "total": len(records),
            "ready": sum(record["status"] == "READY" for record in records),
            "blocked": sum(record["status"] == "BLOCKED" for record in records),
        },
    }
    contest_output = root / "output" / manifest.slug
    invalidate_triage_outputs(root, manifest)
    atomic_json(contest_output / "intake.json", payload)
    atomic_text(contest_output / "INTAKE.md", render_intake_markdown(payload))
    return payload


def render_intake_markdown(payload: dict[str, object]) -> str:
    contest = payload["contest"]
    lines = [f"# {contest['name']} — Intake", ""]
    warnings = contest.get("warnings") or []
    if warnings:
        lines.extend(["## Manifest warnings", ""])
        lines.extend(
            f"- **{warning['severity']}** line {warning['line']}: {warning['message']}"
            for warning in warnings
        )
        lines.append("")
    for record in payload["challenges"]:
        lines.extend([
            f"## [{int(record['number']):02d}] {record['status']} — "
            f"{record['category']}/{record['name']}",
            "",
        ])
        files = record.get("source_paths") or []
        targets = record.get("authorized_targets") or []
        lines.append(f"- Input: {', '.join(Path(path).name for path in files) if files else 'none'}")
        lines.append(f"- Remote: {', '.join(target['declared'] for target in targets) if targets else 'none'}")
        lines.append(f"- Estimated: {record.get('subtype') or record['category']}")
        lines.append(
            f"- Runtime defaults: `{record.get('recommended_image')}` / "
            f"`{record.get('recommended_resource_profile')}`"
        )
        if record.get("containerized_challenge"):
            plan = record.get("service_plan") or {}
            lines.append(
                f"- Local service: `{plan.get('kind')}` / "
                f"{'READY' if plan.get('safe_to_start') else 'NEEDS_REVIEW'}"
            )
        direction = (record.get("hypotheses") or record.get("blockers") or ["none"])[0]
        lines.append(f"- Initial direction: {direction}")
        for warning in record.get("warnings") or []:
            lines.append(
                f"- Manifest warning: **{warning['severity']}** line {warning['line']}: "
                f"{warning['message']}"
            )
        lines.append(
            f"- Solve selector: {int(record['number']):02d} or "
            f"{record['category']}/{record['name']}"
        )
        lines.append("")
    return "\n".join(lines)
