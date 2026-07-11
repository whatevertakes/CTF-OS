"""Conservative candidate verification bound to one live sandbox attempt."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from .parser import ActionObservationParser
from .types import SolverEvent

_DEFAULT_PATTERN = re.compile(r"(?:SCA|KISIA|HACKTHEON|CODEGATE|SSTF|HSPACE|LAYER7|FLAG|CTF|[A-Z0-9_]+)\{[^\r\n{}]+\}")
_PLACEHOLDER = re.compile(r"(?:\{\s*\.\.\.\s*\}|\b(?:example|fake|test|demo|mock|placeholder)\b)", re.IGNORECASE)
_PROOF_PREFIX = "[VERIFICATION_PROOF] "


@dataclass(frozen=True)
class VerificationResult:
    state: str  # rejected | candidate | verified | solved
    candidate: str | None = None
    reason: str = ""


@dataclass(frozen=True)
class VerifierCommand:
    """An argv-only verifier anchored outside worker-writable mounts."""

    argv: tuple[str, ...]
    artifact: Path
    container_path: str
    candidate: str
    challenge_id: str
    attempt_id: str
    nonce: str
    trusted_anchor: bool = False


class Verifier:
    def candidate(self, text: str, *, patterns: Iterable[str] = ()) -> VerificationResult:
        compiled = [re.compile(pattern) for pattern in patterns] or [_DEFAULT_PATTERN]
        for regex in compiled:
            match = regex.search(text)
            if match:
                value = match.group(0)
                if self._is_placeholder(value):
                    return VerificationResult("rejected", value, "placeholder flag")
                return VerificationResult("candidate", value)
        return VerificationResult("rejected", None, "no contest flag pattern matched")

    def verify(
        self,
        text: str,
        *,
        patterns: Iterable[str] = (),
        replay_succeeded: bool = False,
        auto_confirm: bool = False,
    ) -> VerificationResult:
        candidate = self.candidate(text, patterns=patterns)
        if candidate.state != "candidate":
            return candidate
        # This convenience helper deliberately cannot elevate a candidate.
        # Policy booleans and self-reported replay success have no production
        # trust value; only an immutable verifier command could ever do so.
        if replay_succeeded or auto_confirm:
            return VerificationResult("verified", candidate.candidate, "policy-only result; not a production proof")
        return VerificationResult("verified", candidate.candidate, "format accepted; replay verification still required")

    @staticmethod
    def parse_artifact_records(output: str) -> tuple[SolverEvent, ...]:
        return tuple(ActionObservationParser().parse(output))

    def derive_command(
        self,
        records: Iterable[SolverEvent],
        *,
        attempt_workdir: str | Path,
        challenge_artifacts: str | Path,
        candidate: str,
        challenge_id: str,
        attempt_id: str,
        nonce: str,
    ) -> VerifierCommand | None:
        """Refuse worker-authored replay files as production verifiers.

        A nonce and echoed binding prove freshness of *output*, not who made
        the assertion.  Anything below /work or /artifacts is mutable by the
        solver, so it may be preserved/promoted as evidence but can never be a
        production trust anchor.  A future immutable parent-snapshotted
        verifier must construct ``VerifierCommand(..., trusted_anchor=True)``
        from a mount the worker cannot replace.
        """
        if not all(isinstance(value, str) and value for value in (candidate, challenge_id, attempt_id, nonce)):
            raise ValueError("candidate, challenge, attempt, and nonce are required")
        return None

    def declared_artifacts(
        self,
        records: Iterable[SolverEvent],
        *,
        attempt_workdir: str | Path,
        challenge_artifacts: str | Path,
    ) -> tuple[Path, ...]:
        workdir = Path(attempt_workdir)
        artifacts = Path(challenge_artifacts)
        values: list[Path] = []
        for record in records:
            if record.kind != "artifact":
                continue
            path = _artifact_host_path(record.content.strip(), workdir, artifacts)
            # Source authorization and every actual file open happen later in
            # ArtifactWriter through trusted staging dirfds.  Do not resolve
            # or stat a worker-controlled pathname here and reopen it later.
            if path is not None and path not in values:
                values.append(path)
        return tuple(values)

    def verify_sandbox(
        self,
        candidate: str,
        command: VerifierCommand | None,
        *,
        execute: Callable[[tuple[str, ...]], Any],
        patterns: Iterable[str] = (),
    ) -> VerificationResult:
        """Require a fresh structured proof from the same brokered sandbox."""
        preliminary = self.candidate(candidate, patterns=patterns)
        if preliminary.state != "candidate":
            return preliminary
        if command is None:
            return VerificationResult("rejected", candidate, "no explicit live replay artifact was produced")
        if not command.trusted_anchor:
            return VerificationResult("rejected", candidate, "worker-authored replay files are not trusted verifiers")
        try:
            result = execute(command.argv)
        except (OSError, RuntimeError, ValueError) as exc:
            return VerificationResult("rejected", candidate, f"verifier unavailable: {exc}")
        if bool(getattr(result, "timed_out", False)):
            return VerificationResult("rejected", candidate, "replay command timed out")
        if bool(getattr(result, "truncated", False)):
            return VerificationResult("rejected", candidate, "replay output was truncated")
        if int(getattr(result, "returncode", 1)) != 0:
            detail = str(getattr(result, "stderr", "")).strip()
            return VerificationResult("rejected", candidate, detail or "replay command returned non-zero")
        proof = self._extract_bound_proof(str(getattr(result, "stdout", "")), command)
        if proof is None:
            return VerificationResult("rejected", candidate, "missing, malformed, stale, or mismatched verification proof")
        return VerificationResult("solved", candidate, f"fresh replay proof succeeded with {command.container_path}")

    @staticmethod
    def _extract_bound_proof(stdout: str, command: VerifierCommand) -> dict[str, object] | None:
        matches: list[dict[str, object]] = []
        for line in stdout.splitlines():
            if not line.startswith(_PROOF_PREFIX):
                continue
            try:
                parsed = json.loads(line.removeprefix(_PROOF_PREFIX))
            except json.JSONDecodeError:
                return None
            if not isinstance(parsed, dict):
                return None
            matches.append(parsed)
        if len(matches) != 1:
            return None
        proof = matches[0]
        expected = {
            "candidate": command.candidate,
            "challenge_id": command.challenge_id,
            "attempt_id": command.attempt_id,
            "nonce": command.nonce,
        }
        if any(proof.get(key) != value for key, value in expected.items()):
            return None
        return proof

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        if _PLACEHOLDER.search(value):
            return True
        body = value.partition("{")[2].rpartition("}")[0].casefold()
        return any(marker in body for marker in ("example", "fake", "test", "demo", "mock", "placeholder"))


def _artifact_host_path(value: str, workdir: Path, artifacts: Path) -> Path | None:
    """Map one declared container path to its exact private mount counterpart."""
    if not value or any(character.isspace() for character in value) or "\x00" in value:
        return None
    if value == "/work" or value.startswith("/work/"):
        candidate = workdir / value.removeprefix("/work/")
        root = workdir
    elif value == "/artifacts" or value.startswith("/artifacts/"):
        candidate = artifacts / value.removeprefix("/artifacts/")
        root = artifacts
    else:
        return None
    if not candidate.is_absolute() or not root.is_absolute():
        return None
    root_parts = root.parts
    if candidate.parts[:len(root_parts)] != root_parts:
        return None
    remainder = candidate.parts[len(root_parts):]
    if any(part in {"", ".", ".."} for part in remainder):
        return None
    return candidate
