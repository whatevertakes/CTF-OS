from __future__ import annotations

import re
import unicodedata

from .contest import ChallengeSpec


class SelectionError(ValueError):
    def __init__(self, message: str, *, candidates: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.candidates = candidates

    def payload(self) -> dict[str, object]:
        return {"error": str(self), "candidates": list(self.candidates)}


def resolve_selector(challenges: tuple[ChallengeSpec, ...], selector: str) -> ChallengeSpec:
    raw = unicodedata.normalize("NFKC", selector).strip()
    number = re.fullmatch(r"0*([1-9][0-9]*)\s*(?:번(?:\s*문제)?)?", raw)
    if number:
        wanted = int(number.group(1))
        matches = [challenge for challenge in challenges if challenge.number == wanted]
    else:
        folded = raw.casefold()
        exact_key = [c for c in challenges if c.key.casefold() == folded or c.id.casefold() == folded]
        matches = exact_key or [c for c in challenges if c.name.casefold() == folded]
    if len(matches) == 1:
        return matches[0]
    candidates = tuple(f"{c.number:02d} {c.key}" for c in (matches or challenges))
    if not matches:
        raise SelectionError(f"challenge selector did not match: {selector!r}", candidates=candidates)
    raise SelectionError(f"ambiguous challenge selector: {selector!r}", candidates=candidates)
