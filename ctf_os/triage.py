"""Optional legacy/admin whole-contest ranking from explicit Intake artifacts.

This module deliberately consumes Intake artifacts only. It never opens a
prepared challenge file, starts a service, or launches an analysis sandbox.
Python creates a compact, factual context and conservative baseline fields;
the current Sol session supplies only the final ordering through
``finalize_triage``.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .contest import ChallengeSpec, ContestManifest, discover_contests, select_contest
from .workspace import atomic_json, atomic_text, safe_under


class TriageError(ValueError):
    """Raised for a missing, stale, or invalid Challenge Triage artifact."""


TRIAGE_SCHEMA_VERSION = 1
_RECOMMENDATIONS = frozenset({"priority", "hold", "later"})
_TRIAGE_FILES = ("triage-input.json", "TRIAGE-CONTEXT.md", "triage.json", "TRIAGE.md")


def prepare_triage(repo: str | Path, contest_selector: str | None = None) -> dict[str, object]:
    """Build a small, static-only context for a Sol triage decision.

    The only data sources are the current contest manifest and the Intake
    index. The index already carries Intake's inventory, archive, target,
    runtime, and ELF observations, so rereading original challenge input would
    be both slower and outside the phase contract.
    """

    root = Path(repo).resolve()
    manifest = select_contest(discover_contests(root / "incoming"), contest_selector)
    intake, intake_path = _load_intake(root, manifest)
    intake_hash = _sha256_path(intake_path)
    challenge_records = _validated_intake_records(manifest, intake)
    summaries = [_summarize_record(challenge, challenge_records[challenge.id]) for challenge in manifest.challenges]
    _apply_internal_priority_scores(summaries)

    output_dir = _output_dir(root, manifest)
    payload: dict[str, object] = {
        "schema_version": TRIAGE_SCHEMA_VERSION,
        "generated_at": _now(),
        "phase": "CHALLENGE_TRIAGE_PREPARED",
        "source": {
            "contest": manifest.name,
            "contest_slug": manifest.slug,
            "manifest_sha256": manifest.fingerprint,
            "intake_path": str(intake_path),
            "intake_sha256": intake_hash,
        },
        "summary": {
            "total": len(summaries),
            "ready": sum(item["status"] == "READY" for item in summaries),
            "blocked": sum(item["status"] == "BLOCKED" for item in summaries),
        },
        "challenges": summaries,
    }
    input_path = output_dir / "triage-input.json"
    context_path = output_dir / "TRIAGE-CONTEXT.md"
    atomic_json(input_path, payload)
    atomic_text(context_path, render_triage_context(payload))
    return {
        "contest": manifest.name,
        "summary": payload["summary"],
        "input_path": str(input_path),
        "context_path": str(context_path),
        "challenges": [
            {"number": item["number"], "key": item["key"], "status": item["status"]}
            for item in summaries
        ],
    }


def finalize_triage(repo: str | Path, contest_selector: str | None, assessments: object) -> dict[str, object]:
    """Validate Sol's final order and write the user-facing triage Board.

    ``assessments`` contains no free-form technical claims. Reasons select 2--5
    exact fact IDs produced by :func:`prepare_triage`, which keeps the Board
    evidence-backed while the Sol session remains responsible for ranking.
    """

    root = Path(repo).resolve()
    manifest = select_contest(discover_contests(root / "incoming"), contest_selector)
    prepared, input_path = _load_prepared_triage(root, manifest)
    _validate_prepared_source(root, manifest, prepared)
    normalized = _normalize_assessments(assessments, prepared)
    by_number = {item["number"]: item for item in normalized}
    output_records: list[dict[str, object]] = []
    for item in _dict_list(prepared.get("challenges")):
        record = dict(item)
        if record.get("status") == "READY":
            decision = by_number[int(record["number"])]
            facts = {fact["id"]: fact["text"] for fact in _dict_list(record.get("evidence_facts"))}
            record["recommendation"] = {
                "bucket": decision["recommendation"],
                "rank": decision.get("rank"),
                "label": _recommendation_label(decision["recommendation"], decision.get("rank")),
            }
            record["reasons"] = [
                {"fact_id": fact_id, "text": facts[fact_id]}
                for fact_id in decision["reason_fact_ids"]
            ]
        else:
            blockers = [str(value) for value in record.get("blockers", []) if str(value).strip()]
            record["recommendation"] = {"bucket": "blocked", "rank": None, "label": "BLOCKED"}
            record["reasons"] = [{"fact_id": "blocker", "text": value} for value in blockers[:5]]
        # This internal value is kept in JSON only. Markdown exposes Sol's
        # ordinal recommendation, never a numeric priority score.
        output_records.append(record)

    output_records.sort(key=_board_sort_key)
    summary = {
        "total": len(output_records),
        "ready": sum(item["status"] == "READY" for item in output_records),
        "blocked": sum(item["status"] == "BLOCKED" for item in output_records),
        "priority": sum(_mapping(item.get("recommendation")).get("bucket") == "priority" for item in output_records),
        "hold": sum(_mapping(item.get("recommendation")).get("bucket") == "hold" for item in output_records),
        "later": sum(_mapping(item.get("recommendation")).get("bucket") == "later" for item in output_records),
    }
    payload: dict[str, object] = {
        "schema_version": TRIAGE_SCHEMA_VERSION,
        "generated_at": _now(),
        "phase": "CHALLENGE_TRIAGE_FINALIZED",
        "source": dict(prepared["source"]),
        "prepared_input_path": str(input_path),
        "summary": summary,
        "challenges": output_records,
    }
    output_dir = _output_dir(root, manifest)
    result_path = output_dir / "triage.json"
    board_path = output_dir / "TRIAGE.md"
    atomic_json(result_path, payload)
    atomic_text(board_path, render_triage_board(payload))
    return {
        "contest": manifest.name,
        "summary": summary,
        "index_path": str(result_path),
        "board_path": str(board_path),
        "challenges": [
            {
                "number": item["number"], "key": item["key"], "status": item["status"],
                "recommendation": _mapping(item.get("recommendation")).get("label"),
            }
            for item in output_records
        ],
    }


def load_optional_final_triage(
    repo: str | Path, manifest: ContestManifest, challenge: ChallengeSpec,
) -> dict[str, object] | None:
    """Return a current finalized entry without making Triage a solve gate.

    A missing Board and an otherwise valid but stale Board are optional context.
    Unsafe paths and malformed artifacts remain hard failures so optional loading
    cannot hide metadata integrity problems.
    """

    root = Path(repo).resolve()
    path = _output_dir(root, manifest) / "triage.json"
    if path.is_symlink():
        raise TriageError(f"unsafe Challenge Triage index path: {path}")
    if not path.exists():
        return None
    if not path.is_file():
        raise TriageError(f"Challenge Triage index is not a regular file: {path}")

    payload = _read_json(path, "Challenge Triage index")
    if (
        payload.get("schema_version") != TRIAGE_SCHEMA_VERSION
        or payload.get("phase") != "CHALLENGE_TRIAGE_FINALIZED"
    ):
        raise TriageError("Challenge Triage index has an invalid or incomplete schema")
    source_value = payload.get("source")
    if not isinstance(source_value, dict):
        raise TriageError("Challenge Triage index source must be a JSON object")
    source = source_value
    if not isinstance(source.get("manifest_sha256"), str) or not isinstance(source.get("intake_sha256"), str):
        raise TriageError("Challenge Triage index source fingerprints are missing or invalid")
    if source["manifest_sha256"] != manifest.fingerprint:
        return None

    _, intake_path = _load_intake(root, manifest)
    if source["intake_sha256"] != _sha256_path(intake_path):
        return None

    raw_entries = payload.get("challenges")
    if not isinstance(raw_entries, list) or any(not isinstance(entry, dict) for entry in raw_entries):
        raise TriageError("Challenge Triage index challenges must be a list of JSON objects")
    entries = [entry for entry in raw_entries if entry.get("id") == challenge.id]
    if not entries:
        return None
    if len(entries) != 1:
        raise TriageError("Challenge Triage index contains duplicate entries for the selected challenge")
    entry = entries[0]
    if (
        entry.get("number") != challenge.number
        or entry.get("key") != challenge.key
        or entry.get("category") != challenge.category
        or not isinstance(entry.get("recommendation"), dict)
    ):
        raise TriageError("Challenge Triage entry does not match the selected challenge schema")
    return dict(entry)


def require_final_triage(repo: str | Path, manifest: ContestManifest, challenge: ChallengeSpec) -> dict[str, object]:
    """Return a current finalized entry for callers that explicitly require one."""

    entry = load_optional_final_triage(repo, manifest, challenge)
    if entry is None:
        raise TriageError("No current finalized Challenge Triage entry is available")
    if entry.get("status") != "READY":
        raise TriageError(f"selected challenge is not READY in Challenge Triage: {entry.get('reasons', [])}")
    return entry


def invalidate_triage_outputs(repo: str | Path, manifest: ContestManifest) -> None:
    """Remove a Board whenever Intake is regenerated, preventing stale advice."""

    root = Path(repo).resolve()
    output_dir = _output_dir(root, manifest)
    for name in _TRIAGE_FILES:
        path = output_dir / name
        if path.is_symlink():
            raise TriageError(f"unsafe Challenge Triage output path: {path}")
        if path.is_file():
            path.unlink()


def render_triage_context(payload: dict[str, object]) -> str:
    source = _mapping(payload.get("source"))
    summary = _mapping(payload.get("summary"))
    lines = [
        f"# {source.get('contest', 'Contest')} — Challenge Triage Input",
        "",
        "Use only the facts below to set the final order. Do not open challenge input, start services,",
        "run exploits, brute force, symbolic execution, fuzzing, or solvers in this phase.",
        "",
        f"- READY: {summary.get('ready', 0)} / {summary.get('total', 0)}",
        f"- BLOCKED: {summary.get('blocked', 0)}",
        "- Priority score is internal and deliberately omitted from this context.",
        "",
    ]
    for item in _dict_list(payload.get("challenges")):
        lines.extend([f"## [{int(item['number']):02d}] {item['status']} — {item['key']}", ""])
        if item.get("status") != "READY":
            lines.extend(f"- BLOCKED: {reason}" for reason in item.get("blockers", []))
            lines.append("")
            continue
        baseline = _mapping(item.get("baseline"))
        setup = _mapping(item.get("setup"))
        sandbox = _mapping(item.get("recommended_sandbox"))
        playbook = _mapping(item.get("recommended_playbook"))
        lines.extend([
            f"- Baseline difficulty: `{baseline.get('difficulty', 'unknown')}`",
            f"- Baseline solve time: `{baseline.get('estimated_solve_time', 'unknown')}`",
            f"- Baseline success probability: `{baseline.get('success_probability', 'unknown')}`",
            f"- Setup cost: `{setup.get('cost', 'unknown')}`",
            f"- Sandbox: `{sandbox.get('image', 'ctf-os-sandbox:base')}` / `{sandbox.get('resource_profile', 'light')}`",
            f"- Playbook: `{playbook.get('path', 'misc.md')}`",
            "- Evidence facts:",
        ])
        lines.extend(f"  - `{fact['id']}` {fact['text']}" for fact in _dict_list(item.get("evidence_facts")))
        lines.append("")
    return "\n".join(lines)


def render_triage_board(payload: dict[str, object]) -> str:
    source = _mapping(payload.get("source"))
    summary = _mapping(payload.get("summary"))
    lines = [
        f"# {source.get('contest', 'Contest')} — Challenge Triage",
        "",
        f"**READY** {summary.get('ready', 0)} / {summary.get('total', 0)}  ",
        f"**BLOCKED** {summary.get('blocked', 0)}",
        "",
        "## Recommended solve order",
        "",
    ]
    priority = [item for item in _dict_list(payload.get("challenges")) if _mapping(item.get("recommendation")).get("bucket") == "priority"]
    if priority:
        for item in priority:
            lines.extend(_render_board_card(item))
    else:
        lines.append("- No READY challenge received a priority rank.")
        lines.append("")
    for bucket, heading in (("hold", "Hold"), ("later", "Later"), ("blocked", "Blocked")):
        items = [item for item in _dict_list(payload.get("challenges")) if _mapping(item.get("recommendation")).get("bucket") == bucket]
        if not items:
            continue
        lines.extend([f"## {heading}", ""])
        for item in items:
            lines.extend(_render_board_card(item))
    return "\n".join(lines)


def _render_board_card(item: dict[str, object]) -> list[str]:
    recommendation = _mapping(item.get("recommendation"))
    baseline = _mapping(item.get("baseline"))
    setup = _mapping(item.get("setup"))
    sandbox = _mapping(item.get("recommended_sandbox"))
    playbook = _mapping(item.get("recommended_playbook"))
    rank = recommendation.get("rank")
    stars = "⭐" * _star_count(rank) if isinstance(rank, int) else ""
    lines = [f"### {int(item['number']):02d} {item['key']}"]
    if stars:
        lines.append(stars)
    if item.get("status") == "READY":
        setup_text = f"- Setup cost: {_display(setup.get('cost', 'unknown'))}"
        if setup.get("requirements"):
            setup_text += " — " + ", ".join(str(value) for value in setup["requirements"])
        lines.extend([
            f"- Difficulty: {_display(baseline.get('difficulty', 'unknown'))}",
            f"- Estimated: {_display(baseline.get('estimated_solve_time', 'unknown'))}",
            f"- Success probability: {_display(baseline.get('success_probability', 'unknown'))}",
            f"- Initial attack surface: {', '.join(str(value) for value in item.get('initial_attack_surface', [])) or 'Unknown'}",
            setup_text,
            f"- Recommended sandbox: `{sandbox.get('image', 'ctf-os-sandbox:base')}` / `{sandbox.get('resource_profile', 'light')}`",
            f"- Recommended playbook: `{playbook.get('path', 'misc.md')}`",
            f"- {recommendation.get('label', 'Unranked')}",
            "- Reason:",
        ])
    else:
        lines.extend(["- BLOCKED", "- Reason:"])
    reasons = _dict_list(item.get("reasons"))
    lines.extend(f"  - {reason['text']}" for reason in reasons) if reasons else lines.append("  - No usable Intake evidence.")
    lines.append("")
    return lines


def _summarize_record(challenge: ChallengeSpec, record: dict[str, object]) -> dict[str, object]:
    files = _dict_list(record.get("files"))
    metadata = _mapping(record.get("important_metadata"))
    total_bytes = _integer(metadata.get("total_bytes"), sum(_integer(item.get("size")) for item in files))
    file_count = _integer(metadata.get("file_count"), len(files))
    runtime, frameworks = _runtime_and_frameworks(record, files)
    elf_summary = _elf_summary(files)
    requirements = _special_requirements(record, files, runtime, elf_summary)
    permissions = [str(value) for value in _list(record.get("special_permission_requirement")) if str(value).strip()]
    requirements.extend(value for value in permissions if value not in requirements)
    setup = _setup(record, total_bytes, requirements)
    surfaces, matched_surfaces = _attack_surface(challenge, files, frameworks)
    clarity = _clarity(matched_surfaces, frameworks, file_count)
    baseline = _baseline(challenge, setup, clarity)
    sandbox = {
        "image": str(record.get("recommended_image") or "ctf-os-sandbox:base"),
        "resource_profile": str(record.get("recommended_resource_profile") or "light"),
    }
    playbook = {
        "category": challenge.playbook_category,
        "path": f"ctf_os/resources/knowledge/playbooks/{challenge.playbook_category}.md",
    }
    archives = _dict_list(record.get("archives"))
    targets = _dict_list(record.get("authorized_targets"))
    result: dict[str, object] = {
        "number": challenge.number,
        "id": challenge.id,
        "key": challenge.key,
        "category": challenge.category,
        "status": str(record.get("status") or "BLOCKED"),
        "score": challenge.score,
        "description": _compact_text(challenge.description, 320),
        "hint": _compact_text(challenge.hint, 180),
        "authorized_remote_count": len(targets),
        "archive_summary": {
            "count": len(archives),
            "member_count": sum(len(_list(item.get("members"))) for item in archives),
            "source_bytes": sum(_integer(item.get("size")) for item in archives),
        },
        "input_summary": {"file_count": file_count, "total_bytes": total_bytes, "total_size": _human_bytes(total_bytes)},
        "runtime": runtime,
        "frameworks": frameworks,
        "elf_summary": elf_summary,
        "initial_attack_surface": surfaces,
        "attack_surface_clarity": clarity,
        "setup": setup,
        "recommended_sandbox": sandbox,
        "recommended_tools": [str(value) for value in _list(record.get("recommended_tools"))],
        "special_permission_requirement": permissions,
        "needs_review": bool(record.get("needs_review")),
        "recommended_playbook": playbook,
        "baseline": baseline,
        "priority_score": None,
        "blockers": [str(value) for value in record.get("blockers", []) if str(value).strip()],
    }
    result["evidence_facts"] = _facts(result)
    return result


def _runtime_and_frameworks(record: dict[str, object], files: list[dict[str, object]]) -> tuple[list[str], list[str]]:
    paths = {str(item.get("path", "")).casefold() for item in files}
    runtime = {str(value).casefold() for value in _list(record.get("runtime")) if str(value).strip()}
    frameworks: set[str] = set()
    subtype = str(record.get("subtype") or "").strip()
    if subtype:
        frameworks.add(subtype)
    markers = {
        "python": ("requirements.txt", "pyproject.toml", ".py"),
        "node": ("package.json", ".js", ".ts"),
        "java": ("pom.xml", "build.gradle", "build.gradle.kts", ".java", ".jar"),
        "go": ("go.mod", ".go"),
        "rust": ("cargo.toml", ".rs"),
        "php": ("composer.json", ".php"),
        "ruby": ("gemfile", ".rb"),
        "dotnet": (".csproj", ".sln", ".cs"),
    }
    for name, suffixes in markers.items():
        if any(path.endswith(suffix) or path == suffix for path in paths for suffix in suffixes):
            runtime.add(name)
    if any(path.endswith("androidmanifest.xml") or path.endswith(".apk") for path in paths):
        runtime.add("android")
    for label, marker in {
        "Flask": "flask", "Django": "django", "Express": "express",
        "FastAPI": "fastapi", "Spring": "spring", "Laravel": "laravel",
    }.items():
        if any(marker in path for path in paths):
            frameworks.add(label)
    return sorted(runtime), sorted(frameworks)


def _elf_summary(files: list[dict[str, object]]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for item in files:
        elf = _mapping(item.get("elf"))
        if not elf:
            continue
        result.append({
            "path": str(item.get("path", "")), "architecture": elf.get("architecture") or "unknown",
            "type": elf.get("type") or "unknown", "nx": bool(elf.get("nx")),
            "pie": bool(elf.get("pie")), "relro": elf.get("relro") or "unknown",
            "stripped": bool(elf.get("stripped")),
        })
    return result[:5]


def _special_requirements(record: dict[str, object], files: list[dict[str, object]], runtime: list[str], elf_summary: list[dict[str, object]]) -> list[str]:
    requirements: list[str] = []
    service = _mapping(record.get("service_plan"))
    if bool(record.get("containerized_challenge")) or service.get("kind") not in {None, "none"}:
        requirements.append("Docker/Compose service detected")
    if any("arm" in str(item.get("architecture", "")).casefold() or "aarch64" in str(item.get("architecture", "")).casefold() for item in elf_summary):
        requirements.append("ARM-compatible runtime or emulator")
    runtime_set = set(runtime)
    if "java" in runtime_set:
        requirements.append("Java runtime")
    if "android" in runtime_set:
        requirements.append("Android/APK tooling")
    paths = [str(item.get("path", "")).casefold() for item in files]
    if any(path.endswith((".pcap", ".pcapng", ".mem", ".vmem", ".vmdk", ".e01", ".dd", ".img")) for path in paths):
        requirements.append("forensic analysis tooling")
    return requirements


def _setup(record: dict[str, object], total_bytes: int, requirements: list[str]) -> dict[str, object]:
    profile = str(record.get("recommended_resource_profile") or "light")
    input_profile = str(_mapping(record.get("important_metadata")).get("input_profile") or "standard")
    if profile in {"heavy", "large-forensic"} or input_profile == "large-forensic" or total_bytes >= 512 * 1024**2:
        cost = "high"
    elif requirements or bool(record.get("containerized_challenge")) or total_bytes >= 64 * 1024**2:
        cost = "medium"
    else:
        cost = "low"
    return {"cost": cost, "requirements": requirements}


def _attack_surface(challenge: ChallengeSpec, files: list[dict[str, object]], frameworks: list[str]) -> tuple[list[str], list[str]]:
    blob = " ".join(filter(None, [challenge.name, challenge.description or "", challenge.hint or "", *(str(item.get("path", "")) for item in files)])).casefold()
    patterns = {
        "pwn": (("stack overflow", ("bof", "buffer overflow", "stack overflow", "ret2")), ("format string", ("format string", "fmt")), ("heap", ("heap", "tcache", "uaf", "use after free")), ("race", ("race", "toctou"))),
        "web": (("authentication", ("auth", "login", "session", "jwt")), ("file upload", ("upload", "file")), ("SSTI", ("ssti", "template injection", "jinja")), ("SQL injection", ("sqli", "sql injection")), ("JWT", ("jwt",))),
        "crypto": (("RSA", ("rsa",)), ("LCG", ("lcg", "linear congruential")), ("ECC", ("ecc", "elliptic")), ("padding", ("padding", "oracle"))),
        "rev": (("packed binary", ("packed", "upx")), ("obfuscation", ("obfusc",)), ("virtual machine", (" vm", "bytecode", "virtual machine"))),
        "forensic": (("memory", ("memory", ".mem", ".vmem")), ("disk", ("disk", ".vmdk", ".e01", ".dd")), ("image", ("image", ".png", ".jpg", ".jpeg")), ("pcap", ("pcap", ".pcapng"))),
    }
    defaults = {
        "pwn": ["binary input handling", "memory-safety review", "ELF mitigations"],
        "web": ["HTTP routes and request handling", "source/dependency configuration"],
        "crypto": ["parameters and equations", "entropy/implementation assumptions"],
        "rev": ["entry and validation logic", "packing/anti-analysis checks"],
        "forensic": ["file signatures and metadata", "embedded/recovered objects"],
        "misc": ["file/protocol classification", "encoding/runtime constraints"],
        "osint": ["public-source provenance", "DNS/metadata/OCR correlation"],
        "ai": ["model format and preprocessing", "numeric/tokenizer reconstruction"],
        "cloud": ["identity/policy boundaries", "deployment manifests"],
    }
    matched = [label for label, terms in patterns.get(challenge.category, ()) if any(term in blob for term in terms)]
    if challenge.category == "web" and frameworks:
        matched.append("web framework routes")
    return (matched or defaults.get(challenge.category, defaults["misc"]), matched)


def _clarity(matched: list[str], frameworks: list[str], file_count: int) -> str:
    if matched:
        return "clear"
    if frameworks or file_count <= 5:
        return "partial"
    return "limited"


def _baseline(challenge: ChallengeSpec, setup: dict[str, object], clarity: str) -> dict[str, str]:
    text = " ".join(filter(None, [challenge.name, challenge.description or "", challenge.hint or ""])).casefold()
    if any(word in text for word in ("warmup", "beginner", "tutorial", "sanity", "intro", "baby")):
        difficulty = "easy"
    elif any(word in text for word in ("intermediate", "medium")):
        difficulty = "medium"
    elif any(word in text for word in ("advanced", "expert", "hard")):
        difficulty = "hard"
    else:
        difficulty = "unknown"
    cost = str(setup["cost"])
    if difficulty == "easy" and cost == "low":
        estimated = "10~20m"
    elif difficulty == "easy":
        estimated = "20~40m"
    elif cost == "high":
        estimated = "90m+"
    else:
        estimated = "unknown"
    if difficulty == "easy" and clarity == "clear":
        success = "high"
    elif difficulty == "easy":
        success = "medium"
    else:
        success = "unknown"
    return {"difficulty": difficulty, "estimated_solve_time": estimated, "success_probability": success}


def _facts(item: dict[str, object]) -> list[dict[str, str]]:
    prefix = f"{int(item['number']):02d}."
    input_summary = _mapping(item.get("input_summary"))
    archive = _mapping(item.get("archive_summary"))
    facts: list[dict[str, str]] = []

    def add(text: str) -> None:
        facts.append({"id": f"{prefix}f{len(facts) + 1}", "text": text})

    description = item.get("description")
    if description:
        add(f"Declared description: {description}")
    add(f"Prepared input: {input_summary.get('file_count', 0)} files, {input_summary.get('total_size', '0 B')} total.")
    if _integer(archive.get("count")):
        add(f"Archive metadata: {archive.get('count')} archive(s), {archive.get('member_count')} recorded member(s), {_human_bytes(_integer(archive.get('source_bytes')))} source size.")
    runtime = _list(item.get("runtime"))
    frameworks = _list(item.get("frameworks"))
    if runtime or frameworks:
        add("Runtime/framework metadata: " + ", ".join([*(str(value) for value in runtime), *(str(value) for value in frameworks)]) + ".")
    elf = _dict_list(item.get("elf_summary"))
    if elf:
        compact = "; ".join(
            f"{entry['path']} ({entry['architecture']}; NX={'on' if entry['nx'] else 'off'}; PIE={'on' if entry['pie'] else 'off'}; RELRO={entry['relro']}; {'stripped' if entry['stripped'] else 'not stripped'})"
            for entry in elf
        )
        add(f"ELF metadata: {compact}.")
    add("Initial attack surface from category/metadata: " + ", ".join(str(value) for value in _list(item.get("initial_attack_surface"))) + ".")
    setup = _mapping(item.get("setup"))
    requirements = _list(setup.get("requirements"))
    add(f"Setup evidence: {_display(setup.get('cost', 'unknown'))} cost" + ("; " + ", ".join(str(value) for value in requirements) if requirements else "; no special runtime requirement detected") + ".")
    tools = _list(item.get("recommended_tools"))
    if tools:
        add("Recommended installed tools: " + ", ".join(str(value) for value in tools) + ".")
    permissions = _list(item.get("special_permission_requirement"))
    if permissions:
        add("NEEDS_REVIEW permission boundary: " + "; ".join(str(value) for value in permissions) + ".")
    remote_count = _integer(item.get("authorized_remote_count"))
    score = item.get("score")
    add(f"Authorized remote targets: {remote_count}; declared score: {score if score is not None else 'not provided'}.")
    return facts


def _apply_internal_priority_scores(summaries: list[dict[str, object]]) -> None:
    scored = [item for item in summaries if item.get("status") == "READY"]
    points = [int(item["score"]) for item in scored if isinstance(item.get("score"), int)]
    low, high = (min(points), max(points)) if points else (0, 0)
    for item in summaries:
        if item.get("status") != "READY":
            item["priority_score"] = -10_000
            continue
        baseline = _mapping(item.get("baseline"))
        setup = _mapping(item.get("setup"))
        score = 0
        score += {"10~20m": 28, "20~40m": 18, "40~90m": 8, "90m+": -8, "unknown": 4}.get(str(baseline.get("estimated_solve_time")), 0)
        score += {"high": 24, "medium": 12, "low": -6, "unknown": 3}.get(str(baseline.get("success_probability")), 0)
        score += {"low": 14, "medium": 3, "high": -12, "unknown": 0}.get(str(setup.get("cost")), 0)
        score += {"clear": 12, "partial": 5, "limited": 0}.get(str(item.get("attack_surface_clarity")), 0)
        score -= min(6, 2 * _integer(item.get("authorized_remote_count")))
        total = _integer(_mapping(item.get("input_summary")).get("total_bytes"))
        if total >= 512 * 1024**2:
            score -= 10
        elif total >= 64 * 1024**2:
            score -= 4
        if _list(_mapping(item.get("setup")).get("requirements")):
            score -= 3
        for elf in _dict_list(item.get("elf_summary")):
            score -= sum((bool(elf.get("nx")), bool(elf.get("pie")), elf.get("relro") == "full"))
        # Points are only a modest value signal, never a claim about organizer
        # difficulty semantics. Sol receives raw points and may override this.
        point = item.get("score")
        if isinstance(point, int) and high > low:
            score += round(6 * (point - low) / (high - low))
        item["priority_score"] = score


def _normalize_assessments(assessments: object, prepared: dict[str, object]) -> list[dict[str, object]]:
    raw = _mapping(assessments).get("assessments") if isinstance(assessments, dict) else assessments
    items = _dict_list(raw)
    ready = [item for item in _dict_list(prepared.get("challenges")) if item.get("status") == "READY"]
    expected = {int(item["number"]): item for item in ready}
    if len(items) != len(expected):
        raise TriageError(f"expected one assessment for each READY challenge ({len(expected)}), received {len(items)}")
    normalized: list[dict[str, object]] = []
    seen: set[int] = set()
    for raw_item in items:
        number = _integer(raw_item.get("number"), -1)
        if number not in expected or number in seen:
            raise TriageError("assessment numbers must be unique READY challenge numbers")
        seen.add(number)
        recommendation = str(raw_item.get("recommendation") or "").casefold()
        if recommendation not in _RECOMMENDATIONS:
            raise TriageError("assessment recommendation must be priority, hold, or later")
        rank_value = raw_item.get("rank")
        if recommendation == "priority":
            if isinstance(rank_value, bool) or not isinstance(rank_value, int) or rank_value < 1:
                raise TriageError("priority assessment requires a positive integer rank")
            rank: int | None = rank_value
        else:
            if rank_value is not None and rank_value != "":
                raise TriageError("hold/later assessment must not include a rank")
            rank = None
        fact_ids = [str(value) for value in _list(raw_item.get("reason_fact_ids"))]
        if not 2 <= len(fact_ids) <= 5 or len(set(fact_ids)) != len(fact_ids):
            raise TriageError("each READY assessment requires 2-5 unique reason_fact_ids")
        allowed = {fact["id"] for fact in _dict_list(expected[number].get("evidence_facts"))}
        if not set(fact_ids).issubset(allowed):
            raise TriageError(f"assessment {number} cites a fact outside its prepared evidence")
        normalized.append({"number": number, "recommendation": recommendation, "rank": rank, "reason_fact_ids": fact_ids})
    ranks = sorted(item["rank"] for item in normalized if item["recommendation"] == "priority")
    if ranks != list(range(1, len(ranks) + 1)):
        raise TriageError("priority ranks must be contiguous from 1")
    return normalized


def _load_prepared_triage(root: Path, manifest: ContestManifest) -> tuple[dict[str, object], Path]:
    path = _output_dir(root, manifest) / "triage-input.json"
    if not path.is_file() or path.is_symlink():
        raise TriageError("Challenge Triage input not found; run triage-prepare after Intake")
    payload = _read_json(path, "Challenge Triage input")
    if payload.get("phase") != "CHALLENGE_TRIAGE_PREPARED" or payload.get("schema_version") != TRIAGE_SCHEMA_VERSION:
        raise TriageError("Challenge Triage input schema is unsupported; rerun triage-prepare")
    return payload, path


def _validate_prepared_source(root: Path, manifest: ContestManifest, prepared: dict[str, object]) -> None:
    source = _mapping(prepared.get("source"))
    if source.get("manifest_sha256") != manifest.fingerprint:
        raise TriageError("contest.md changed after triage preparation; rerun Intake and triage-prepare")
    _, intake_path = _load_intake(root, manifest)
    if source.get("intake_sha256") != _sha256_path(intake_path):
        raise TriageError("Intake changed after triage preparation; rerun triage-prepare")


def _load_intake(root: Path, manifest: ContestManifest) -> tuple[dict[str, object], Path]:
    path = _output_dir(root, manifest) / "intake.json"
    if not path.is_file() or path.is_symlink():
        raise TriageError("Intake index not found; run Intake before Challenge Triage")
    payload = _read_json(path, "Intake index")
    if _mapping(payload.get("contest")).get("manifest_sha256") != manifest.fingerprint:
        raise TriageError("contest.md changed after Intake; rerun Intake before Challenge Triage")
    return payload, path


def _validated_intake_records(manifest: ContestManifest, intake: dict[str, object]) -> dict[str, dict[str, object]]:
    records = _dict_list(intake.get("challenges"))
    by_id = {str(record.get("id")): record for record in records}
    expected = {challenge.id for challenge in manifest.challenges}
    if set(by_id) != expected or len(records) != len(by_id):
        raise TriageError("Intake index does not contain exactly the current contest challenges; rerun Intake")
    return by_id


def _output_dir(root: Path, manifest: ContestManifest) -> Path:
    return safe_under(root / "output", Path(manifest.slug))


def _board_sort_key(item: dict[str, object]) -> tuple[int, int, int]:
    recommendation = _mapping(item.get("recommendation"))
    bucket = str(recommendation.get("bucket"))
    order = {"priority": 0, "hold": 1, "later": 2, "blocked": 3}.get(bucket, 4)
    rank = recommendation.get("rank")
    return order, int(rank) if isinstance(rank, int) else 10_000, int(item["number"])


def _recommendation_label(bucket: str, rank: object) -> str:
    if bucket == "priority" and isinstance(rank, int):
        return f"Priority #{rank}"
    return {"hold": "Hold", "later": "Later"}.get(bucket, "Unranked")


def _star_count(rank: object) -> int:
    return max(1, 6 - min(rank, 5)) if isinstance(rank, int) and rank > 0 else 0


def _display(value: object) -> str:
    return str(value).replace("unknown", "Unknown").replace("easy", "Easy").replace("medium", "Medium").replace("hard", "Hard").replace("high", "High").replace("low", "Low")


def _compact_text(value: str | None, limit: int) -> str | None:
    if not value:
        return None
    text = re.sub(r"\s+", " ", value).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _human_bytes(value: int) -> str:
    amount = max(0, value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TiB"


def _read_json(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TriageError(f"{label} is unreadable: {path}") from exc
    if not isinstance(payload, dict):
        raise TriageError(f"{label} must be a JSON object")
    return payload


def _sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _dict_list(value: object) -> list[dict[str, Any]]:
    return [item for item in _list(value) if isinstance(item, dict)]


def _list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _integer(value: object, default: int = 0) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default
