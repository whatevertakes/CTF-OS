"""Difficulty-based, intentionally diverse local attempt plans."""

from __future__ import annotations

from dataclasses import dataclass
from secrets import token_hex
from typing import Callable
from uuid import uuid4

from .category_planner import ExecutionContract, SolvePlan


@dataclass(frozen=True)
class AttemptProfile:
    name: str
    role: str
    purpose: str
    max_runtime_sec: int


ATTEMPT_PROFILES: dict[str, AttemptProfile] = {
    "recon_fast": AttemptProfile("recon_fast", "recon", "fast file, remote, and description reconnaissance", 300),
    "recon_deep": AttemptProfile("recon_deep", "recon", "deep initial reconnaissance", 900),
    "exploit_fast": AttemptProfile("exploit_fast", "exploit", "quickly recover a simple vulnerability", 600),
    "exploit_main": AttemptProfile("exploit_main", "exploit", "implement the most likely strategy", 1200),
    "exploit_alt": AttemptProfile("exploit_alt", "exploit", "compete using a different strategy", 1200),
    "source_deep": AttemptProfile("source_deep", "source", "deep source or binary analysis", 1500),
    "fallback": AttemptProfile("fallback", "fallback", "discard assumptions and find a new approach", 1200),
    "verifier": AttemptProfile("verifier", "verifier", "verify a flag candidate", 300),
}

_PROFILE_NAMES = {
    "easy": ("recon_fast", "exploit_fast"),
    "medium": ("recon_fast", "exploit_main", "exploit_alt"),
    "hard": ("recon_deep", "source_deep", "exploit_main", "exploit_alt", "fallback"),
}


@dataclass(frozen=True)
class RaceAttempt:
    attempt_id: str
    strategy_seed: str
    profile: AttemptProfile
    contract: ExecutionContract | None = None

    @property
    def strategy_instruction(self) -> str:
        if self.contract is not None:
            return self.contract.objective
        if self.profile.name == "exploit_main":
            return "Use the strongest evidence-backed vulnerability hypothesis from reconnaissance."
        if self.profile.name == "exploit_alt":
            return (
                "Do not repeat exploit_main or failed approaches. Prioritize a different input "
                "path, vulnerability class, or analysis tool."
            )
        if self.profile.name == "fallback":
            return "Reinterpret the challenge from scratch and consider unusual edge cases."
        return self.profile.purpose.capitalize() + "."


@dataclass(frozen=True)
class RacePlan:
    difficulty: str
    attempts: tuple[RaceAttempt, ...]

    @classmethod
    def from_solve_plan(
        cls, plan: SolvePlan, *, id_factory: Callable[[], str] | None = None,
        seed_factory: Callable[[], str] | None = None,
    ) -> "RacePlan":
        make_id = id_factory or (lambda: uuid4().hex)
        make_seed = seed_factory or (lambda: token_hex(8))
        profiles = {
            "terra_high": AttemptProfile("contract_terra_high", "implementer", "execute a concrete solve contract", 1200),
            "luna_medium": AttemptProfile("contract_luna_medium", "recon", "answer a narrow branch question", 600),
            "sol_high": AttemptProfile("contract_sol_high", "source", "resolve a hard conceptual fork", 1500),
        }
        return cls(
            difficulty="contract",
            attempts=tuple(RaceAttempt(make_id(), make_seed(), profiles[item.worker], item) for item in plan.contracts),
        )

    @classmethod
    def for_score(
        cls,
        score: int,
        *,
        id_factory: Callable[[], str] | None = None,
        seed_factory: Callable[[], str] | None = None,
    ) -> "RacePlan":
        """Return a full plan; 401--499 is treated as medium to avoid an uncovered gap."""
        if score < 0:
            raise ValueError("score must be non-negative")
        difficulty = "easy" if score <= 200 else "medium" if score < 500 else "hard"
        make_id = id_factory or (lambda: uuid4().hex)
        make_seed = seed_factory or (lambda: token_hex(8))
        return cls(
            difficulty=difficulty,
            attempts=tuple(
                RaceAttempt(make_id(), make_seed(), ATTEMPT_PROFILES[name])
                for name in _PROFILE_NAMES[difficulty]
            ),
        )

    @classmethod
    def build(
        cls,
        score: int,
        *,
        id_factory: Callable[[], str] | None = None,
        seed_factory: Callable[[], str] | None = None,
    ) -> "RacePlan":
        return cls.for_score(score, id_factory=id_factory, seed_factory=seed_factory)
