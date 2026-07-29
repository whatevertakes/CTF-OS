"""Proof evaluation independent from candidate discovery and submission."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from ctf_os.adapters.base import ProofPolicy


@dataclass(frozen=True, slots=True)
class ProofAttempt:
    run_id: str
    exit_code: int
    candidate_values: tuple[str, ...]
    source_manifest_sha256: str
    clean_workspace: bool
    remote: bool = False
    timed_out: bool = False
    artifact_ids: tuple[str, ...] = ()

    @property
    def command_completed(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


@dataclass(frozen=True, slots=True)
class ProofResult:
    passed: bool
    candidate: str
    policy_mode: str
    successful_attempts: int
    required_attempts: int
    total_attempts: int
    source_manifest_sha256: str
    failures: tuple[str, ...]
    run_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def evaluate_proof(
    candidate: str,
    source_manifest_sha256: str,
    attempts: Iterable[ProofAttempt],
    policy: ProofPolicy,
) -> ProofResult:
    """Evaluate clean attempts; discovery alone can never pass this gate."""

    values = tuple(attempts)
    failures: list[str] = []
    successful = 0
    for attempt in values:
        prefix = attempt.run_id
        if attempt.source_manifest_sha256 != source_manifest_sha256:
            failures.append(f"{prefix}: source manifest mismatch")
            continue
        if not attempt.clean_workspace:
            failures.append(f"{prefix}: workspace was not clean")
            continue
        if not attempt.command_completed:
            reason = "timed out" if attempt.timed_out else (
                f"exit code {attempt.exit_code}"
            )
            failures.append(f"{prefix}: {reason}")
            continue
        if candidate not in attempt.candidate_values:
            failures.append(f"{prefix}: exact candidate was not reproduced")
            continue
        successful += 1

    if policy.mode == "success_distribution":
        required_total = policy.trial_count
        rate = successful / len(values) if values else 0.0
        minimum = policy.minimum_success_rate
        if len(values) < required_total:
            failures.append(
                f"only {len(values)}/{required_total} required trials completed"
            )
        if minimum is None:
            failures.append("success_distribution policy has no minimum rate")
        elif rate < minimum:
            failures.append(
                f"success rate {rate:.3f} is below required {minimum:.3f}"
            )
        required_successes = (
            math.ceil(required_total * minimum)
            if minimum is not None
            else required_total
        )
        passed = (
            len(values) >= required_total
            and minimum is not None
            and rate >= minimum
        )
    else:
        remote_required = policy.remote_repetitions
        local_required = policy.clean_repetitions
        local_success = sum(
            1
            for attempt in values
            if not attempt.remote
            and attempt.source_manifest_sha256 == source_manifest_sha256
            and attempt.clean_workspace
            and attempt.command_completed
            and candidate in attempt.candidate_values
        )
        remote_success = sum(
            1
            for attempt in values
            if attempt.remote
            and attempt.source_manifest_sha256 == source_manifest_sha256
            and attempt.clean_workspace
            and attempt.command_completed
            and candidate in attempt.candidate_values
        )
        if local_success < local_required:
            failures.append(
                f"only {local_success}/{local_required} clean local reproductions"
            )
        if remote_success < remote_required:
            failures.append(
                f"only {remote_success}/{remote_required} remote reproductions"
            )
        required_successes = local_required + remote_required
        passed = (
            local_success >= local_required
            and remote_success >= remote_required
        )

    return ProofResult(
        passed=passed,
        candidate=candidate,
        policy_mode=policy.mode,
        successful_attempts=successful,
        required_attempts=required_successes,
        total_attempts=len(values),
        source_manifest_sha256=source_manifest_sha256,
        failures=tuple(dict.fromkeys(failures)),
        run_ids=tuple(attempt.run_id for attempt in values),
    )


def write_proof_result(directory: Path, result: ProofResult) -> Path:
    """Persist a small proof result atomically; raw runs remain external."""

    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "result.json"
    temporary = directory / ".result.json.tmp"
    payload = json.dumps(
        result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True
    )
    with temporary.open("w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.write("\n")
        handle.flush()
        import os

        os.fsync(handle.fileno())
    temporary.replace(path)
    return path


def proof_result_sha256(result: ProofResult) -> str:
    encoded = json.dumps(
        result.to_dict(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()

