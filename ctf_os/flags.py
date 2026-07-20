from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shlex
import shutil

from .evidence import append_evidence
from .workspace import (
    atomic_json, atomic_text, challenge_workspace, ensure_run_mutable, is_run_root,
    read_jsonl_strict, resolve_active_run, state_lock,
)


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
    local_success_marker: str | None = None,
    remote_flag_candidate: str | None = None,
    remote_exploit_confirmed: bool | None = None,
    exploit_path_matched: bool = True,
    same_flag_required: bool = False,
    local_success_pattern: str | None = None,
    remote_success_pattern: str | None = None,
) -> dict[str, object]:
    compatibility_root = root
    root = resolve_active_run(root, input_fingerprint=input_fingerprint)
    frozen_remote_state: dict[str, object] | None = None
    try:
        ensure_run_mutable(root)
    except ValueError as exc:
        try:
            current = json.loads((root / "STATE.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise FlagVerificationError(str(exc)) from exc
        if isinstance(current, dict) and current.get("remote_flag_receipt") and not current.get("sealed"):
            frozen_remote_state = current
        else:
            raise FlagVerificationError(str(exc)) from exc
    if root != compatibility_root.resolve(strict=False):
        _adopt_legacy_verification_inputs(compatibility_root, root)
    local_marker = local_success_marker if local_success_marker is not None else (flag if local_reproduced else None)
    remote_flag = remote_flag_candidate if remote_flag_candidate is not None else (flag if has_remote and remote_reproduced else None)
    selected_flag = remote_flag or flag or local_marker or ""
    if frozen_remote_state is not None and selected_flag != frozen_remote_state.get("flag_candidate"):
        raise FlagVerificationError("replay cannot replace a receipt-bound remote flag candidate")
    pattern_match = matches_flag(selected_flag, pattern)
    remote_pattern_match = bool(remote_flag and matches_flag(remote_flag, pattern))
    remote_confirmed = remote_reproduced if remote_exploit_confirmed is None else remote_exploit_confirmed
    verification = {
        "local_reproduction": local_reproduced,
        "remote_reproduction": remote_confirmed if has_remote else None,
        "independent_rerun": independent_rerun, "flag_pattern": pattern_match,
        "placeholder_rejected": not _is_placeholder(selected_flag),
        "local_reproduced": local_reproduced,
        "local_success_marker": local_marker,
        "remote_exploit_confirmed": remote_confirmed if has_remote else False,
        "remote_flag_obtained": remote_pattern_match if has_remote else False,
        "remote_flag_pattern_matched": remote_pattern_match if has_remote else False,
        "remote_flag_candidate": remote_flag,
        "same_flag_required": same_flag_required,
        "same_flag": bool(local_marker and remote_flag and local_marker == remote_flag) if has_remote else None,
        "exploit_path_matched": exploit_path_matched if has_remote else True,
    }
    recorded = _verify_evidence_receipts(
        root / "evidence.log", {"local": local_marker, "independent": local_marker, "remote": remote_flag},
        evidence_refs or {}, has_remote, remote_hosts, input_fingerprint,
    )
    verification["recorded_evidence"] = recorded
    exploit_root = root / "exploit"
    exploit_present = exploit_root.is_dir() and any(
        path.is_file() and not path.is_symlink() for path in exploit_root.rglob("*")
    )
    verification["exploit_present"] = exploit_present
    local_evidence_ok = all(recorded["matches"].get(kind) is not None for kind in ("local", "independent")) if require_recorded_evidence else True
    remote_evidence_ok = recorded["matches"].get("remote") is not None if require_recorded_evidence and has_remote else True
    local_exploit_confirmed = bool(local_reproduced and independent_rerun and local_marker and exploit_present and local_evidence_ok)
    remote_exploit_proven = bool(has_remote and remote_confirmed and remote_evidence_ok)
    remote_flag_obtained = bool(has_remote and remote_flag and remote_pattern_match and remote_evidence_ok)
    same_flag_ok = not same_flag_required or bool(local_marker and remote_flag and local_marker == remote_flag)
    if has_remote:
        fully_verified = bool(local_exploit_confirmed and remote_exploit_proven and remote_flag_obtained and exploit_path_matched and same_flag_ok)
        if fully_verified:
            verdict = "FULLY_VERIFIED"
        elif remote_flag_obtained:
            verdict = "REMOTE_FLAG_OBTAINED"
        elif remote_exploit_proven:
            verdict = "REMOTE_EXPLOIT_CONFIRMED"
        elif local_exploit_confirmed:
            verdict = "LOCAL_EXPLOIT_CONFIRMED"
        elif local_reproduced:
            verdict = "LOCAL_REPRODUCED"
        else:
            verdict = "BLOCKED"
    else:
        fully_verified = local_exploit_confirmed and pattern_match
        verdict = (
            "FULLY_VERIFIED" if fully_verified else
            "LOCAL_EXPLOIT_CONFIRMED" if local_exploit_confirmed else
            "LOCAL_REPRODUCED" if local_reproduced else "BLOCKED"
        )
    verification.update({
        "local_exploit_confirmed": local_exploit_confirmed,
        "remote_exploit_confirmed": remote_exploit_proven,
        "remote_flag_obtained": remote_flag_obtained,
        "fully_verified": fully_verified,
        "verdict": verdict,
    })
    # Strict replay may prove behavior, but a remote terminal/submission state is
    # receipt-bound. Replay alone never manufactures REMOTE_FLAG_OBTAINED.
    ready = fully_verified
    state_path = root / "STATE.json"
    with state_lock(root):
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if input_fingerprint is not None and state.get("input_fingerprint") != input_fingerprint:
            raise FlagVerificationError("challenge input fingerprint changed during verification")
        remote_receipt_bound = bool(state.get("remote_flag_receipt"))
        if has_remote and not remote_receipt_bound:
            ready = False
        state.update({
            "status": "READY_FOR_HUMAN_SUBMISSION" if ready else "VERIFICATION_REQUIRED",
            "competition_state": "FULLY_VERIFIED" if fully_verified and (not has_remote or remote_receipt_bound) else (
                "REMOTE_FLAG_OBTAINED" if remote_flag_obtained and remote_receipt_bound else
                "LOCAL_FLAG_OBTAINED" if local_reproduced and pattern_match else
                "FLAG_CANDIDATE" if selected_flag else None
            ),
            "submission_recommended": bool(ready or (remote_flag_obtained and remote_receipt_bound)),
            "remote_flag": remote_flag if remote_flag_obtained and remote_receipt_bound else state.get("remote_flag"),
            "flag_candidate": selected_flag or None, "verification": verification,
            "replay_verdict": verdict,
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
            "same_flag_required": same_flag_required,
        }
        if remote_argv:
            contract["remote_argv"] = remote_argv
        if local_success_pattern:
            contract["local_success_pattern"] = local_success_pattern
        if remote_success_pattern:
            contract["remote_success_pattern"] = remote_success_pattern
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
            f"- Status: **{state['status']}**", f"- Replay verdict: **{verdict}**",
            f"- Flag candidate: `{selected_flag}`", "",
            "## Verification", "",
            f"- Local reproduction: {'success' if local_reproduced else 'not verified'}",
            f"- Remote reproduction: {'success' if remote_confirmed else ('not required' if not has_remote else 'not verified')}",
            f"- Independent rerun: {'success' if independent_rerun else 'not verified'}",
            f"- Flag pattern: {'match' if pattern_match else 'mismatch'}", "",
            "## Reproduce", "", f"`bash {root / 'reproduce.sh'}`", "",
            "The human must submit the flag manually. No submission was attempted.",
        ]
        atomic_text(root / "RESULT.md", "\n".join(result) + "\n")
        append_evidence(root / "evidence.log", "result_verification", {"flag_candidate": selected_flag or None, "ready": ready, "verification": verification})
        if root != compatibility_root.resolve(strict=False):
            # Non-authoritative compatibility outputs keep old direct callers
            # working; all terminal state remains authoritative under runs/.
            atomic_text(compatibility_root / "RESULT.md", (root / "RESULT.md").read_text(encoding="utf-8"))
            atomic_json(
                compatibility_root / "REPRODUCE.json",
                json.loads((root / "REPRODUCE.json").read_text(encoding="utf-8")),
            )
            atomic_text(compatibility_root / "reproduce.sh", (root / "reproduce.sh").read_text(encoding="utf-8"))
            (compatibility_root / "reproduce.sh").chmod(0o755)
            if (compatibility_root / "STATE.json").is_file():
                compatibility_state = dict(state)
                compatibility_state["compatibility_view"] = True
                compatibility_state["authoritative_state"] = str((root / "STATE.json").relative_to(compatibility_root))
                atomic_json(compatibility_root / "STATE.json", compatibility_state)
    return {"ready_for_human_submission": ready, "status": state["status"], "verdict": verdict, "verification": verification, "result_path": str(root / "RESULT.md")}


def _adopt_legacy_verification_inputs(workspace: Path, run: Path) -> None:
    source_exploit = workspace / "exploit"
    target_exploit = run / "exploit"
    if source_exploit.is_dir() and not source_exploit.is_symlink() and not target_exploit.exists():
        for item in source_exploit.rglob("*"):
            if item.is_symlink():
                raise FlagVerificationError("legacy exploit compatibility input contains a symlink")
        shutil.copytree(source_exploit, target_exploit)
    source_evidence = workspace / "evidence.log"
    target_evidence = run / "evidence.log"
    if source_evidence.is_file() and not source_evidence.is_symlink():
        source_text = source_evidence.read_text(encoding="utf-8")
        if source_text and (not target_evidence.is_file() or not target_evidence.read_text(encoding="utf-8")):
            atomic_text(target_evidence, source_text)


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
    resolved = challenge_workspace(root) if is_run_root(root) else root.resolve()
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
    path: Path, expected: dict[str, str | None], refs: dict[str, str], has_remote: bool, remote_hosts: tuple[str, ...],
    input_fingerprint: str | None,
) -> dict[str, object]:
    required = ["local", "independent"] + (["remote"] if has_remote else [])
    records: list[dict[str, object]] = []
    if path.is_file():
        try:
            evidence_rows = read_jsonl_strict(path, "evidence ledger")
        except ValueError as exc:
            raise FlagVerificationError(str(exc)) from exc
        for record in evidence_rows:
            fingerprint_ok = input_fingerprint is None or record.get("input_fingerprint") == input_fingerprint
            if record.get("event") == "replay_exec" and record.get("exit_code") == 0 and fingerprint_ok:
                records.append(record)
    matches: dict[str, int | None] = {}
    used: set[int] = set()
    for kind in required:
        reference = refs.get(kind, "")
        found = None
        for index, record in enumerate(records):
            candidate = expected.get(kind)
            serialized = json.dumps(record, ensure_ascii=False, sort_keys=True)
            configured_hosts = {str(item.get("host")) for item in record.get("authorized_targets", []) if isinstance(item, dict)}
            remote_ok = kind != "remote" or (record.get("authorized_network_observed") is True and bool(configured_hosts.intersection(remote_hosts)))
            candidate_ok = candidate in str(record.get("stdout", "")) if candidate else kind == "remote"
            if index not in used and reference and reference in serialized and remote_ok and candidate_ok:
                found = index
                break
        matches[kind] = found
        if found is not None:
            used.add(found)
    return {"complete": all(matches[kind] is not None for kind in required), "matches": matches, "required": required}
