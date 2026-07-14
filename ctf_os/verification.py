"""Adaptive flag receipts and the competition fast path.

Strict replay remains available in :mod:`ctf_os.replay`, but a valid remote
receipt may immediately produce SUBMISSION_RECOMMENDED for human submission.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .delegation import utc_now
from .evidence import append_evidence
from .flags import matches_flag
from .sandbox.network import Target, target_matches_observation
from .workspace import atomic_json, atomic_text, state_lock


FLAG_STATES = frozenset({
    "FLAG_CANDIDATE", "LOCAL_FLAG_OBTAINED", "REMOTE_FLAG_OBTAINED",
    "SUBMISSION_RECOMMENDED", "FULLY_VERIFIED", "SUBMITTED_BY_HUMAN",
})


class FastFlagError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RemoteFlagReceipt:
    receipt_id: str
    branch_id: str
    candidate: str
    target: dict[str, Any]
    network_observed: bool
    command_argv: tuple[str, ...]
    output_digest: str
    output_excerpt: str
    exploit_artifact: str
    input_fingerprint: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1, "receipt_id": self.receipt_id,
            "branch_id": self.branch_id, "candidate": self.candidate,
            "target": self.target, "network_observed": self.network_observed,
            "command_argv": list(self.command_argv), "output_digest": self.output_digest,
            "output_excerpt": self.output_excerpt, "exploit_artifact": self.exploit_artifact,
            "input_fingerprint": self.input_fingerprint, "created_at": self.created_at,
        }


def record_remote_flag(
    root: Path, *, challenge_id: str, input_fingerprint: str, branch_id: str,
    declared_targets: Sequence[Target], observed_host: str, observed_port: int,
    observed_protocol: str, network_observed: bool, output: str,
    candidate: str, flag_pattern: str | None, command_argv: Sequence[str],
    exploit_artifact: str,
) -> dict[str, Any]:
    if not network_observed:
        raise FastFlagError("REMOTE_FLAG_OBTAINED requires an actual network observation")
    matches = [
        target for target in declared_targets
        if target_matches_observation(target, observed_host, observed_port, observed_protocol)
    ]
    if len(matches) != 1:
        raise FastFlagError("remote receipt target is not the current challenge's declared target")
    if candidate not in output:
        raise FastFlagError("flag candidate was not present in the preserved command output")
    argv = tuple(_argv(command_argv))
    artifact = _relative_artifact(exploit_artifact)
    artifact_path = (root / artifact).resolve()
    try:
        artifact_path.relative_to(root.resolve())
    except ValueError as exc:
        raise FastFlagError("exploit artifact escapes the challenge workspace") from exc
    if artifact_path.is_symlink() or not artifact_path.is_file():
        raise FastFlagError("remote flag receipt requires an existing exploit artifact")
    pattern_match = matches_flag(candidate, flag_pattern)
    placeholder = _looks_placeholder(candidate)
    confidence = "HIGH" if pattern_match and not placeholder else "LOW"
    state_name = "SUBMISSION_RECOMMENDED" if confidence == "HIGH" else "FLAG_CANDIDATE"
    receipt_id = hashlib.sha256(
        json.dumps({
            "branch": branch_id, "candidate": candidate, "host": observed_host,
            "port": observed_port, "protocol": observed_protocol, "argv": argv,
            "output": hashlib.sha256(output.encode()).hexdigest(),
        }, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:24]
    receipt = RemoteFlagReceipt(
        receipt_id=receipt_id, branch_id=branch_id, candidate=candidate,
        target={
            "declared": matches[0].declared, "host": observed_host,
            "port": observed_port, "protocol": observed_protocol,
        }, network_observed=True, command_argv=argv,
        output_digest=hashlib.sha256(output.encode()).hexdigest(),
        output_excerpt=_bounded_excerpt(output, candidate), exploit_artifact=artifact,
        input_fingerprint=input_fingerprint, created_at=utc_now(),
    )
    receipt_path = root / "flag-receipts" / f"remote-{receipt_id}.json"
    state_path = root / "STATE.json"
    with state_lock(root):
        if receipt_path.is_symlink():
            raise FastFlagError("remote flag receipt path must not be a symlink")
        if not receipt_path.exists():
            atomic_json(receipt_path, receipt.to_dict())
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if state.get("challenge_id") != challenge_id or state.get("input_fingerprint") != input_fingerprint:
            raise FastFlagError("challenge identity or input fingerprint changed during flag recording")
        history = list(state.get("flag_history") or [])
        if not any(row.get("receipt_id") == receipt_id for row in history if isinstance(row, Mapping)):
            history.append({
                "receipt_id": receipt_id, "candidate": candidate,
                "state": "REMOTE_FLAG_OBTAINED" if pattern_match else "FLAG_CANDIDATE",
                "confidence": confidence, "created_at": receipt.created_at,
            })
        state.update({
            "status": state_name, "competition_state": state_name,
            "flag_candidate": candidate, "remote_flag": candidate if pattern_match else None,
            "submission_recommended": state_name == "SUBMISSION_RECOMMENDED",
            "remote_flag_receipt": str(receipt_path.relative_to(root)),
            "flag_history": history, "updated_at": utc_now(),
        })
        atomic_json(state_path, state)
        _write_fast_result(
            root, challenge_id=challenge_id, state=state_name, candidate=candidate,
            confidence=confidence, receipt_path=receipt_path, target=matches[0],
        )
    append_evidence(root / "evidence.log", "remote_flag_receipt", {
        "receipt_id": receipt_id, "branch_id": branch_id, "candidate": candidate,
        "target": receipt.target, "network_observed": True,
        "input_fingerprint": input_fingerprint, "confidence": confidence,
    })
    return {
        "state": state_name, "remote_state": "REMOTE_FLAG_OBTAINED" if pattern_match else "FLAG_CANDIDATE",
        "challenge_id": challenge_id, "flag": candidate, "confidence": confidence,
        "source": "declared remote", "receipt": str(receipt_path),
        "recommendation": "submit immediately" if confidence == "HIGH" else "verify candidate provenance",
        "full_clean_replay_required_before_human_submission": False,
        "branch_actions": {
            "prioritize": branch_id, "stop_low_value_branches": confidence == "HIGH",
            "maximum_verifiers_to_keep": 1 if confidence == "HIGH" else None,
        },
        "automatic_submission_attempted": False,
    }


def mark_fully_verified(root: Path, *, input_fingerprint: str) -> dict[str, Any]:
    state_path = root / "STATE.json"
    with state_lock(root):
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if state.get("input_fingerprint") != input_fingerprint:
            raise FastFlagError("challenge input fingerprint changed")
        if not state.get("flag_candidate"):
            raise FastFlagError("cannot mark FULLY_VERIFIED without a flag candidate")
        state["competition_state"] = "FULLY_VERIFIED"
        state["status"] = "FULLY_VERIFIED"
        state["submission_recommended"] = True
        state["updated_at"] = utc_now()
        atomic_json(state_path, state)
    return {"state": "FULLY_VERIFIED", "flag": state["flag_candidate"]}


def _write_fast_result(
    root: Path, *, challenge_id: str, state: str, candidate: str,
    confidence: str, receipt_path: Path, target: Target,
) -> None:
    body = (
        f"# Remote flag — {challenge_id}\n\n"
        f"- State: **{state}**\n- Flag: `{candidate}`\n- Confidence: **{confidence}**\n"
        f"- Source: declared remote `{target.host}:{target.port}`\n"
        f"- Receipt: `{receipt_path.relative_to(root)}`\n"
        "- Recommendation: submit immediately\n"
        "- Full clean replay: not required before human submission\n\n"
        "Submission remains manual; CTF-OS did not contact a CTFd submission endpoint.\n"
    )
    atomic_text(root / "RESULT.md", body)


def _argv(values: Sequence[str]) -> list[str]:
    if isinstance(values, (str, bytes)) or not values or len(values) > 256:
        raise FastFlagError("remote command receipt requires a direct argv array")
    result = []
    forbidden = {";", "&&", "||", "|", ">", ">>", "<", "&"}
    for value in values:
        text = str(value)
        if not text or text in forbidden or "\n" in text or "\r" in text:
            raise FastFlagError("remote command receipt must not contain shell operators")
        result.append(text)
    return result


def _relative_artifact(value: str) -> str:
    path = Path(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise FastFlagError("exploit artifact must be a safe relative path")
    return path.as_posix()


def _looks_placeholder(candidate: str) -> bool:
    normalized = candidate.casefold()
    return any(word in normalized for word in ("...", "example", "placeholder", "dummy", "sample", "your_flag", "yourflag"))


def _bounded_excerpt(output: str, candidate: str) -> str:
    index = output.find(candidate)
    start = max(0, index - 256)
    end = min(len(output), index + len(candidate) + 256)
    return output[start:end].replace("\x00", "\\0")
