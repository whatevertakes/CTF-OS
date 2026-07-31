"""Streaming parser for ``codex exec --json`` JSONL events."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from ctf_os.candidates import (
    FlagNotificationError,
    candidate_value_is_valid,
    flag_notification_error,
    looks_like_generic_code_noise,
)

DEFAULT_FLAG_PATTERNS = (
    r"(?<![A-Za-z0-9_])[A-Za-z][A-Za-z0-9_]{1,31}\{[^{}\r\n]{1,512}\}",
)
DEFAULT_FLAG_CANDIDATE_LIMIT = 1024
DEFAULT_FLAG_CANDIDATE_CHARS_LIMIT = 256 * 1024
DEFAULT_EVENT_COUNT_LIMIT = 10_000
DEFAULT_MALFORMED_LINE_COUNT_LIMIT = 1_000


@dataclass(frozen=True)
class Usage:
    input_tokens: int = 0
    cached_input_tokens: int = 0
    output_tokens: int = 0
    reasoning_output_tokens: int = 0

    def __add__(self, other: "Usage") -> "Usage":
        return Usage(
            self.input_tokens + other.input_tokens,
            self.cached_input_tokens + other.cached_input_tokens,
            self.output_tokens + other.output_tokens,
            self.reasoning_output_tokens + other.reasoning_output_tokens,
        )


@dataclass(frozen=True)
class FlagCandidate:
    value: str
    event_type: str
    source: str = "event_stream"


@dataclass(frozen=True)
class CodexEvent:
    event_type: str
    payload: Mapping[str, Any]
    raw_line: str


@dataclass(frozen=True)
class ExecutionFailure:
    kind: str
    message: str
    retryable: bool
    event_type: str


def _string_values(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for nested in value.values():
            yield from _string_values(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _string_values(nested)


class FlagDetector:
    def __init__(
        self,
        patterns: Iterable[str] = DEFAULT_FLAG_PATTERNS,
        *,
        candidate_limit: int = DEFAULT_FLAG_CANDIDATE_LIMIT,
        candidate_chars_limit: int = DEFAULT_FLAG_CANDIDATE_CHARS_LIMIT,
        suppress_generic_code_noise: bool = False,
    ) -> None:
        compiled = tuple(re.compile(pattern) for pattern in patterns)
        if not compiled:
            raise ValueError("at least one flag pattern is required")
        if candidate_limit < 0:
            raise ValueError("candidate_limit must not be negative")
        if candidate_chars_limit < 0:
            raise ValueError("candidate_chars_limit must not be negative")
        self._patterns = compiled
        self._seen: set[str] = set()
        self._candidate_limit = candidate_limit
        self._candidate_chars_limit = candidate_chars_limit
        self._suppress_generic_code_noise = suppress_generic_code_noise
        self.accepted_chars = 0
        self.suppressed_matches = 0
        self.code_noise_suppressed_matches = 0

    def _accept(
        self,
        candidate: str,
        event_type: str,
        source: str,
    ) -> FlagCandidate | None:
        if not candidate_value_is_valid(candidate):
            return None
        if candidate in self._seen:
            return None
        if (
            len(self._seen) >= self._candidate_limit
            or self.accepted_chars + len(candidate)
            > self._candidate_chars_limit
        ):
            self.suppressed_matches += 1
            return None
        self._seen.add(candidate)
        self.accepted_chars += len(candidate)
        return FlagCandidate(candidate, event_type, source)

    def scan(self, value: Any, event_type: str, source: str = "event_stream") -> list[FlagCandidate]:
        candidates: list[FlagCandidate] = []
        for text in _string_values(value):
            for pattern in self._patterns:
                for match in pattern.finditer(text):
                    if (
                        self._suppress_generic_code_noise
                        and looks_like_generic_code_noise(
                            match.group(0),
                            source=source,
                            context=text,
                            position=match.start(),
                        )
                    ):
                        self.suppressed_matches += 1
                        self.code_noise_suppressed_matches += 1
                        continue
                    candidate = self._accept(
                        match.group(0),
                        event_type,
                        source,
                    )
                    if candidate is not None:
                        candidates.append(candidate)
        return candidates

    def report_candidate(
        self,
        value: object,
        event_type: str,
        source: str = "structured_output",
    ) -> FlagCandidate | None:
        """Accept an explicitly typed candidate under the same bounded quota."""

        if not isinstance(value, str):
            return None
        return self._accept(value, event_type, source)

    def release(self, candidates: Iterable[FlagCandidate]) -> None:
        """Release failed and unattempted notifications for a later retry."""

        for candidate in candidates:
            if candidate.value not in self._seen:
                continue
            self._seen.remove(candidate.value)
            self.accepted_chars -= len(candidate.value)


def _event_type(payload: Mapping[str, Any]) -> str:
    value = payload.get("type", payload.get("event_type", "unknown"))
    return value if isinstance(value, str) else "unknown"


def _usage_from_payload(payload: Mapping[str, Any]) -> Usage:
    usage = payload.get("usage")
    if not isinstance(usage, Mapping):
        return Usage()

    def token(name: str) -> int:
        value = usage.get(name, 0)
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0

    return Usage(
        input_tokens=token("input_tokens"),
        cached_input_tokens=token("cached_input_tokens"),
        output_tokens=token("output_tokens"),
        reasoning_output_tokens=token("reasoning_output_tokens"),
    )


def _failure_from_payload(payload: Mapping[str, Any], event_type: str) -> ExecutionFailure | None:
    if event_type not in {"turn.failed", "error"}:
        return None
    error = payload.get("error")
    if isinstance(error, Mapping):
        kind_value = error.get("code", error.get("type", event_type))
        message_value = error.get("message", error)
    else:
        kind_value = payload.get("code", event_type)
        message_value = payload.get("message", error if error is not None else payload)
    kind = kind_value if isinstance(kind_value, str) else event_type
    message = message_value if isinstance(message_value, str) else json.dumps(message_value, sort_keys=True)
    retryable_codes = {"rate_limit", "rate_limit_exceeded", "server_error", "timeout", "overloaded"}
    retryable = kind.lower() in retryable_codes or any(
        marker in message.lower() for marker in ("rate limit", "temporar", "timeout", "overload")
    )
    return ExecutionFailure(kind, message, retryable, event_type)


@dataclass
class EventAccumulator:
    detector: FlagDetector = field(default_factory=FlagDetector)
    on_event: Callable[[CodexEvent], None] | None = None
    on_flag: Callable[[FlagCandidate], None] | None = None
    max_events: int = DEFAULT_EVENT_COUNT_LIMIT
    max_malformed_lines: int = DEFAULT_MALFORMED_LINE_COUNT_LIMIT
    events: list[CodexEvent] = field(default_factory=list, init=False)
    flags: list[FlagCandidate] = field(default_factory=list, init=False)
    failures: list[ExecutionFailure] = field(default_factory=list, init=False)
    usage: Usage = field(default_factory=Usage, init=False)
    thread_id: str | None = field(default=None, init=False)
    malformed_lines: list[str] = field(default_factory=list, init=False)
    events_dropped: int = field(default=0, init=False)
    malformed_lines_dropped: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if self.max_events < 0:
            raise ValueError("max_events must not be negative")
        if self.max_malformed_lines < 0:
            raise ValueError("max_malformed_lines must not be negative")

    def _record_malformed(self, raw_line: str) -> None:
        if len(self.malformed_lines) < self.max_malformed_lines:
            self.malformed_lines.append(raw_line)
        else:
            self.malformed_lines_dropped += 1

    def notify_candidates(
        self,
        candidates: Iterable[FlagCandidate],
    ) -> list[FlagCandidate]:
        """Notify candidates transactionally with respect to detector quota."""

        pending = list(candidates)
        for index, candidate in enumerate(pending):
            if self.on_flag is not None:
                try:
                    self.on_flag(candidate)
                except BaseException as error:
                    self.detector.release(pending[index:])
                    if not isinstance(error, Exception):
                        raise
                    if isinstance(error, FlagNotificationError):
                        raise
                    raise flag_notification_error(error) from error
            self.flags.append(candidate)
        return pending

    def feed(self, line: str) -> CodexEvent | None:
        raw_line = line.rstrip("\r\n")
        if not raw_line:
            return None
        try:
            payload = json.loads(raw_line)
        except json.JSONDecodeError:
            self._record_malformed(raw_line)
            self.notify_candidates(
                self.detector.scan(raw_line, "malformed", "raw_jsonl")
            )
            return None
        if not isinstance(payload, Mapping):
            self._record_malformed(raw_line)
            self.notify_candidates(
                self.detector.scan(payload, "malformed", "raw_jsonl")
            )
            return None
        event_type = _event_type(payload)
        event = CodexEvent(event_type, payload, raw_line)
        if len(self.events) < self.max_events:
            self.events.append(event)
        else:
            self.events_dropped += 1
        if self.on_event is not None:
            self.on_event(event)

        if event_type == "thread.started":
            possible_id = payload.get("thread_id", payload.get("thread", payload.get("id")))
            if isinstance(possible_id, Mapping):
                possible_id = possible_id.get("id")
            if isinstance(possible_id, str):
                self.thread_id = possible_id

        self.usage = self.usage + _usage_from_payload(payload)
        failure = _failure_from_payload(payload, event_type)
        if failure is not None:
            self.failures.append(failure)

        self.notify_candidates(self.detector.scan(payload, event_type))
        return event

    def scan_final(self, value: Any) -> list[FlagCandidate]:
        candidates = self.detector.scan(value, "final.output", "structured_output")
        if isinstance(value, Mapping):
            explicit = value.get("flag_candidates")
            if isinstance(explicit, list):
                for item in explicit:
                    if not isinstance(item, Mapping):
                        continue
                    candidate = self.detector.report_candidate(
                        item.get("value"),
                        "final.output",
                        "structured_output",
                    )
                    if candidate is not None:
                        candidates.append(candidate)
        return self.notify_candidates(candidates)
