"""Deterministic semantic progress and plateau detection.

Exact duplicate strings remain one weak signal.  Final decisions also account
for command/input/artifact identity, normalized failure clusters and progress.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from hashlib import sha256
import json
import re
import shlex
from typing import Any, Mapping


def _normalise(value: str) -> str:
    value = value.casefold()
    value = re.sub(r"0x[0-9a-f]+", "<addr>", value)
    value = re.sub(r"\b\d{4}-\d\d?-\d\d?[t ][0-9:.+z-]+", "<timestamp>", value)
    value = re.sub(r"/(?:[^\s/:]+/)+[^\s:]+", "<path>", value)
    value = re.sub(r"\b\d{5,}\b", "<number>", value)
    return " ".join(value.split())


def _command(value: str) -> str:
    try:
        parts = shlex.split(value)
    except ValueError:
        return _normalise(value)
    if not parts:
        return ""
    executable = parts[0].rsplit("/", 1)[-1].casefold()
    normalized = [executable]
    for item in parts[1:]:
        if re.fullmatch(r"(?:0x)?[0-9a-fA-F]{6,}|\d{5,}", item):
            normalized.append("<value>")
        else:
            normalized.append(_normalise(item))
    return " ".join(normalized)


def _fingerprint(value: str) -> str:
    return sha256(_normalise(value).encode()).hexdigest()[:20]


@dataclass(frozen=True)
class ProgressSnapshot:
    attempt_id: str = ""
    command: str = ""
    executable: str = ""
    arguments: tuple[str, ...] = ()
    input_hash: str = ""
    artifact_hash: str = ""
    environment_hash: str = ""
    strategy: str = ""
    goal: str = ""
    hypothesis: str = ""
    exit_code: int | None = None
    output: str = ""
    failure_class: str = ""
    crash_signature: str = ""
    new_artifacts: int = 0
    artifact_changes: int = 0
    new_evidence: int = 0
    new_endpoints: int = 0
    new_parameters: int = 0
    new_leaks: int = 0
    new_primitives: int = 0
    classification_changed: bool = False
    constraint_delta: int = 0
    coverage_delta: float = 0.0
    verifier_delta: float = 0.0
    reliability_delta: float = 0.0
    hypothesis_eliminated: bool = False
    contract_transition: str = ""
    model: str = ""

    @property
    def progress_score(self) -> float:
        positive = (self.new_evidence + self.new_artifacts + self.artifact_changes * .5 +
                    self.new_endpoints + self.new_parameters * .5 + self.new_leaks * 3 +
                    self.new_primitives * 4 + self.constraint_delta * .5 + self.coverage_delta +
                    self.verifier_delta * 2 + self.reliability_delta * 2 +
                    (1.0 if self.classification_changed else 0.0) +
                    (1.0 if self.hypothesis_eliminated else 0.0))
        return positive - (0.25 if self.exit_code not in (None, 0) else 0.0)


@dataclass(frozen=True)
class SemanticLoopResult:
    loop: bool
    plateau: bool
    confidence: float
    reason: str
    related_attempt_ids: tuple[str, ...] = ()
    cluster: str = ""
    progress_delta: float = 0.0
    recommended_action: str = "continue"
    change: str = ""


@dataclass(frozen=True)
class LoopSignal:
    shift_required: bool
    reason: str = ""
    count: int = 0
    semantic: SemanticLoopResult | None = None


class LoopDetector:
    def __init__(self, *, repeat_threshold: int = 2, window: int = 8) -> None:
        if repeat_threshold < 2:
            raise ValueError("repeat_threshold must be at least two")
        self.repeat_threshold = repeat_threshold
        self._commands: Counter[str] = Counter()
        self._failures: Counter[str] = Counter()
        self._history: deque[ProgressSnapshot] = deque(maxlen=window)
        self._clusters: Counter[str] = Counter()
        self._cluster_tokens: dict[str, frozenset[str]] = {}

    def observe_command(self, command: str) -> LoopSignal:
        return self._observe(self._commands, command, "repeated command")

    def observe_failure(self, failure: str) -> LoopSignal:
        return self._observe(self._failures, failure, "repeated failure")

    def observe(self, kind: str, content: str) -> LoopSignal:
        if kind.lower() == "action":
            return self.observe_command(content)
        if kind.lower() == "fail":
            return self.observe_failure(content)
        return LoopSignal(False)

    def observe_snapshot(self, snapshot: ProgressSnapshot) -> SemanticLoopResult:
        command_key = _command(snapshot.command)
        failure_material = snapshot.failure_class or snapshot.crash_signature or snapshot.output
        failure_key = self._failure_cluster(failure_material) if failure_material else ""
        semantic_key = json.dumps({
            "command": command_key, "input": snapshot.input_hash,
            "artifact": snapshot.artifact_hash, "strategy": snapshot.strategy,
            "hypothesis": _normalise(snapshot.hypothesis), "failure": failure_key,
        }, sort_keys=True)
        cluster = sha256(semantic_key.encode()).hexdigest()[:16]
        if failure_key:
            # Group same normalized root cause even when model wording, raw
            # addresses, paths or timestamps differ.
            cluster = failure_key
            self._clusters[cluster] += 1
        prior = tuple(self._history)
        self._history.append(snapshot)
        score = snapshot.progress_score
        if score > 0:
            return SemanticLoopResult(False, False, 0.05, "new semantic progress", cluster=cluster,
                                      progress_delta=score, recommended_action="continue")
        identical_semantics = [item for item in prior if (
            _command(item.command) == command_key and item.input_hash == snapshot.input_hash
            and item.artifact_hash == snapshot.artifact_hash
            and _normalise(item.hypothesis) == _normalise(snapshot.hypothesis)
        )]
        failure_count = self._clusters[cluster] if failure_key else 0
        count = max(len(identical_semantics) + 1, failure_count)
        loop = count >= self.repeat_threshold
        recent_scores = [item.progress_score for item in (*prior[-(self.repeat_threshold - 1):], snapshot)]
        plateau = (loop or failure_count >= self.repeat_threshold) and len(recent_scores) >= self.repeat_threshold and sum(recent_scores) <= 0
        confidence = min(.99, .45 + .15 * count + (.15 if plateau else 0)) if loop or plateau else .1
        attempts = tuple(dict.fromkeys(item.attempt_id for item in (*identical_semantics, snapshot) if item.attempt_id))
        reason = ("same semantic failure cluster without progress" if failure_count >= self.repeat_threshold
                  else "same command, input, artifact and hypothesis without progress" if loop
                  else "recent attempts produced no semantic progress" if plateau else "no loop")
        return SemanticLoopResult(loop, plateau, confidence, reason, attempts, cluster,
                                  score, "replan" if loop or plateau else "continue",
                                  "strategy_or_hypothesis" if loop or plateau else "")

    def _failure_cluster(self, value: str) -> str:
        normalized = _normalise(value)
        stop = {"the", "a", "an", "is", "was", "and", "or", "to", "of", "for", "with", "failed", "failure", "error"}
        tokens = frozenset(token for token in re.findall(r"[a-z_<>]{2,}", normalized) if token not in stop)
        for key, prior in self._cluster_tokens.items():
            union = tokens | prior
            if union and len(tokens & prior) / len(union) >= 0.6:
                return key
        key = _fingerprint(normalized)
        self._cluster_tokens[key] = tokens
        return key

    def _observe(self, records: Counter[str], value: str, label: str) -> LoopSignal:
        key = _normalise(value)
        if not key:
            return LoopSignal(False)
        records[key] += 1
        count = records[key]
        return LoopSignal(count >= self.repeat_threshold, f"{label}: {value}" if count >= self.repeat_threshold else "", count)
