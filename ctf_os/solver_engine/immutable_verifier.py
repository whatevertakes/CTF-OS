"""Parent-owned candidate verifier for randomized local benchmark fixtures.

Only an HMAC key and expected tag live in the coordinator process. Neither the
reference flag nor the verifier material is serialized, mounted, prompted, or
written to the event log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import secrets


@dataclass(frozen=True, slots=True)
class ParentVerificationResult:
    valid: bool
    verifier_id: str
    candidate_sha256: str
    reason: str


@dataclass(frozen=True, slots=True)
class ParentOwnedVerifier:
    challenge_id: str
    verifier_id: str
    _key: bytes = field(repr=False)
    _expected_tag: bytes = field(repr=False)

    @classmethod
    def from_flag(
        cls, *, challenge_id: str, flag: str, verifier_id: str = "benchmark-parent-v1",
        key: bytes | None = None,
    ) -> "ParentOwnedVerifier":
        if not challenge_id or not flag or not verifier_id:
            raise ValueError("challenge_id, flag, and verifier_id are required")
        material = key or secrets.token_bytes(32)
        if len(material) < 32:
            raise ValueError("parent verifier key must contain at least 256 bits")
        expected = hmac.digest(material, flag.encode("utf-8"), "sha256")
        return cls(challenge_id, verifier_id, material, expected)

    def verify(self, *, challenge_id: str, candidate: str) -> ParentVerificationResult:
        digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
        if challenge_id != self.challenge_id:
            return ParentVerificationResult(False, self.verifier_id, digest, "challenge binding mismatch")
        actual = hmac.digest(self._key, candidate.encode("utf-8"), "sha256")
        valid = hmac.compare_digest(actual, self._expected_tag)
        return ParentVerificationResult(
            valid, self.verifier_id, digest,
            "parent-owned verification succeeded" if valid else "candidate rejected by parent-owned verifier",
        )
