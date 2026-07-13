from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shlex

from .evidence import append_evidence
from .workspace import atomic_json, atomic_text, state_lock


class FlagVerificationError(ValueError):
    pass


_ELLIPSIS_PLACEHOLDER = re.compile(r"\A[A-Za-z0-9_]+\{\.\.\.\}\Z", re.I)
_TOKEN_PLACEHOLDER = re.compile(r"\A[A-Za-z0-9_]+\{(?:example|placeholder|dummy|sample|test|fake)(?:[-_0-9]*)\}\Z", re.I)


def _is_placeholder(flag: str) -> bool:
    if _ELLIPSIS_PLACEHOLDER.fullmatch(flag) or _TOKEN_PLACEHOLDER.fullmatch(flag):
        return True
    match = re.fullmatch(r"[A-Za-z0-9_]+\{([^{}]+)\}", flag)
    if not match:
        return False
    normalized = re.sub(r"[^a-z0-9]+", "", match.group(1).casefold())
    return normalized in {
        "yourflaghere", "exampleflag", "thisisatest", "redacted", "todo",
        "changeme", "replacewithflag", "insertflaghere", "notarealflag",
    }


def matches_flag(flag: str, pattern: str | None) -> bool:
    if not flag or "\n" in flag or "\r" in flag or _is_placeholder(flag):
        return False
    if pattern is None:
        return bool(re.fullmatch(r"[A-Za-z0-9_]{2,32}\{[^{}\r\n]+\}", flag))
    try:
        return re.fullmatch(pattern, flag) is not None
    except re.error as exc:
        raise FlagVerificationError(f"invalid manifest flag pattern: {exc}") from exc


def verify_and_record(
    root: Path, *, flag: str, pattern: str | None, has_remote: bool,
    local_reproduced: bool, remote_reproduced: bool, independent_rerun: bool,
    reproduce_command: str | None = None,
    reproduce_argv: list[str] | None = None,
    image_profile: str = "base",
    resource_profile: str = "standard",
    service_required: bool = False,
    remote_argv: list[str] | None = None,
    evidence_refs: dict[str, str] | None = None,
    require_recorded_evidence: bool = True,
    remote_hosts: tuple[str, ...] = (),
    input_fingerprint: str | None = None,
) -> dict[str, object]:
    pattern_match = matches_flag(flag, pattern)
    verification = {
        "local_reproduction": local_reproduced,
        "remote_reproduction": remote_reproduced if has_remote else None,
        "independent_rerun": independent_rerun, "flag_pattern": pattern_match,
        "placeholder_rejected": not _is_placeholder(flag),
    }
    recorded = _verify_evidence_receipts(
        root / "evidence.log", flag, evidence_refs or {}, has_remote, remote_hosts, input_fingerprint,
    )
    verification["recorded_evidence"] = recorded
    exploit_root = root / "exploit"
    exploit_present = exploit_root.is_dir() and any(
        path.is_file() and not path.is_symlink() for path in exploit_root.rglob("*")
    )
    verification["exploit_present"] = exploit_present
    evidence_ok = recorded["complete"] if require_recorded_evidence else True
    ready = local_reproduced and independent_rerun and pattern_match and exploit_present and evidence_ok and (remote_reproduced if has_remote else True)
    state_path = root / "STATE.json"
    with state_lock(root):
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if input_fingerprint is not None and state.get("input_fingerprint") != input_fingerprint:
            raise FlagVerificationError("challenge input fingerprint changed during verification")
        state.update({
            "status": "READY_FOR_HUMAN_SUBMISSION" if ready else "VERIFICATION_REQUIRED",
            "flag_candidate": flag, "verification": verification,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        atomic_json(state_path, state)
        argv = reproduce_argv or _legacy_argv(reproduce_command)
        contract = {
            "schema_version": 1,
            "image_profile": image_profile,
            "resource_profile": resource_profile,
            "service_required": service_required,
            "argv": argv,
            "expected_flag_pattern": pattern,
            "input_fingerprint": input_fingerprint or state.get("input_fingerprint"),
        }
        if remote_argv:
            contract["remote_argv"] = remote_argv
        atomic_json(root / "REPRODUCE.json", contract)
        repo, contest, selector = _replay_coordinates(root, state)
        reproduce = (
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            "SCRIPT_DIR=\"$(cd -- \"$(dirname -- \"${BASH_SOURCE[0]}\")\" && pwd)\"\n"
            f"exec uv run python -m ctf_os.agent_tools --repo {shlex.quote(str(repo))} "
            f"replay {shlex.quote(selector)} --contest {shlex.quote(contest)}\n"
        )
        atomic_text(root / "reproduce.sh", reproduce)
        (root / "reproduce.sh").chmod(0o755)
        result = [
            f"# Result — {state.get('challenge_id', 'challenge')}", "",
            f"- Status: **{state['status']}**", f"- Flag candidate: `{flag}`", "",
            "## Verification", "",
            f"- Local reproduction: {'success' if local_reproduced else 'not verified'}",
            f"- Remote reproduction: {'success' if remote_reproduced else ('not required' if not has_remote else 'not verified')}",
            f"- Independent rerun: {'success' if independent_rerun else 'not verified'}",
            f"- Flag pattern: {'match' if pattern_match else 'mismatch'}", "",
            "## Reproduce", "", f"`bash {root / 'reproduce.sh'}`", "",
            "The human must submit the flag manually. No submission was attempted.",
        ]
        atomic_text(root / "RESULT.md", "\n".join(result) + "\n")
        append_evidence(root / "evidence.log", "result_verification", {"flag_candidate": flag, "ready": ready, "verification": verification})
    return {"ready_for_human_submission": ready, "status": state["status"], "verification": verification, "result_path": str(root / "RESULT.md")}


def _legacy_argv(command: str | None) -> list[str]:
    """Migrate the old command field without ever embedding it in a shell script."""
    if not command:
        raise FlagVerificationError("structured reproduce argv is required")
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise FlagVerificationError(f"invalid reproduce command: {exc}") from exc
    shell_tokens = {";", "&&", "||", "|", ">", ">>", "<", "2>", "&"}
    if not argv or any(token in shell_tokens or "\n" in token or "\r" in token for token in argv):
        raise FlagVerificationError("reproduce command must be a direct argv without shell operators")
    if argv[0] == "python":
        argv[0] = "python3"
    return argv


def _replay_coordinates(root: Path, state: dict[str, object]) -> tuple[Path, str, str]:
    resolved = root.resolve()
    try:
        if resolved.parents[2].name != "output":
            raise IndexError
        repo = resolved.parents[3]
        contest = resolved.parents[1].name
    except IndexError as exc:
        raise FlagVerificationError("challenge result is not below repository output/<contest>/<category>/<challenge>") from exc
    selector = str(state.get("challenge_id", ""))
    if not selector:
        raise FlagVerificationError("STATE.json has no challenge_id")
    return repo, contest, selector


def _verify_evidence_receipts(
    path: Path, flag: str, refs: dict[str, str], has_remote: bool, remote_hosts: tuple[str, ...],
    input_fingerprint: str | None,
) -> dict[str, object]:
    required = ["local", "independent"] + (["remote"] if has_remote else [])
    records: list[dict[str, object]] = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            fingerprint_ok = input_fingerprint is None or record.get("input_fingerprint") == input_fingerprint
            if record.get("event") == "replay_exec" and record.get("exit_code") == 0 and flag in str(record.get("stdout", "")) and fingerprint_ok:
                records.append(record)
    matches: dict[str, int | None] = {}
    used: set[int] = set()
    for kind in required:
        reference = refs.get(kind, "")
        found = None
        for index, record in enumerate(records):
            serialized = json.dumps(record, ensure_ascii=False, sort_keys=True)
            configured_hosts = {str(item.get("host")) for item in record.get("authorized_targets", []) if isinstance(item, dict)}
            remote_ok = kind != "remote" or (record.get("authorized_network_observed") is True and bool(configured_hosts.intersection(remote_hosts)))
            if index not in used and reference and reference in serialized and remote_ok:
                found = index
                break
        matches[kind] = found
        if found is not None:
            used.add(found)
    return {"complete": all(matches[kind] is not None for kind in required), "matches": matches, "required": required}
