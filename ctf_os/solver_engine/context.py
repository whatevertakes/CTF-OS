"""Build a normalized, prompt-safe view of challenge intake information."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping


def _strings(values: Iterable[object] | None) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        values = (values,)
    return tuple(str(value).strip() for value in (values or ()) if str(value).strip())


@dataclass(frozen=True)
class ChallengeContext:
    challenge_id: str
    title: str
    category: str
    score: int
    description: str
    files: tuple[str, ...] = ()
    findings: tuple[str, ...] = ()
    failed_strategies: tuple[str, ...] = ()
    failed_commands: tuple[str, ...] = ()
    allowed_remotes: tuple[str, ...] = ()
    hints: tuple[str, ...] = ()


class ChallengeContextBuilder:
    """Accept contest metadata plus local evidence without accessing the host."""

    def build(
        self,
        metadata: Mapping[str, Any],
        *,
        files: Iterable[object] | None = None,
        findings: Iterable[object] | None = None,
        failed_strategies: Iterable[object] | None = None,
        failed_commands: Iterable[object] | None = None,
        allowed_remotes: Iterable[object] | None = None,
    ) -> ChallengeContext:
        challenge_id = str(metadata.get("id") or metadata.get("slug") or metadata.get("title") or "challenge")
        title = str(metadata.get("title") or metadata.get("name") or challenge_id)
        try:
            score = int(metadata.get("score", 0))
        except (TypeError, ValueError) as exc:
            raise ValueError("challenge score must be an integer") from exc
        if score < 0:
            raise ValueError("challenge score must be non-negative")
        return ChallengeContext(
            challenge_id=challenge_id,
            title=title,
            category=str(metadata.get("category") or "misc").lower(),
            score=score,
            description=str(metadata.get("description") or ""),
            files=_strings(files if files is not None else metadata.get("files") or metadata.get("file")),
            findings=_strings(findings if findings is not None else metadata.get("findings")),
            failed_strategies=_strings(failed_strategies if failed_strategies is not None else metadata.get("failed_strategies")),
            failed_commands=_strings(failed_commands if failed_commands is not None else metadata.get("failed_commands") or metadata.get("tried_commands")),
            allowed_remotes=_strings(allowed_remotes if allowed_remotes is not None else metadata.get("allowed_remotes") or metadata.get("remotes") or metadata.get("remote")),
            hints=_strings(metadata.get("hints")),
        )
