"""Category-aware, intentionally diverse local CTF solve portfolios."""

from __future__ import annotations

from dataclasses import dataclass
from secrets import token_hex
from typing import Callable
from uuid import uuid4

from ..categories import canonical_solver_category


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

# These are executable search directions, not reporting roles.  Each attempt
# gets a different tool path so parallel workers do not merely repeat the same
# generic analysis with a different model seed.
_CATEGORY_STRATEGIES: dict[str, dict[str, str]] = {
    "pwn": {
        "recon": "Classify architecture and mitigations with file/checksec/readelf; map the input path and crash surface.",
        "source": "Recover the exact corruption primitive with static analysis plus a debugger; record offsets, constraints, and controlled state.",
        "main": "Build and run a local pwntools exploit from the strongest primitive, then adapt the proven exploit to the authorized remote.",
        "alt": "Pursue a different primitive or exploitation family (ROP, format string, heap, race, or logic) and prove control locally.",
        "fallback": "Restart from observable program behavior; fuzz narrow inputs and use debugger traces to discover a missed primitive.",
    },
    "rev": {
        "recon": "Identify format, architecture, packing, imports, strings, and likely input/compare boundaries.",
        "source": "Run static decompilation and dynamic debugging as competing paths; extract the exact acceptance constraints.",
        "main": "Implement a keygen, decoder, emulator, or symbolic solver and execute it against the challenge binary.",
        "alt": "Use a different representation: patch/trace the comparison, emulate, or solve constraints symbolically.",
        "fallback": "Recheck anti-analysis, runtime-generated code, custom VM, and hidden data transformations from a clean trace.",
    },
    "crypto": {
        "recon": "Classify the construction and parameters; extract samples and test invariants with a short Python/Sage script.",
        "source": "Derive the weakest violated assumption and rank concrete attack families by parameter fit.",
        "main": "Implement the best-fitting attack in Python/Sage/Z3 and validate it by re-encryption, round-trip, or supplied samples.",
        "alt": "Implement an independent attack family or algebraic formulation and compare executable outputs.",
        "fallback": "Reparse encodings and parameters, test edge cases/oracles, and search for nonce, RNG, padding, or composition mistakes.",
    },
    "web": {
        "recon": "Map routes, methods, parameters, cookies, redirects, and source/runtime stack while preserving a reproducible session.",
        "source": "Trace attacker-controlled input to privilege, file, template, query, deserialization, or command boundaries in source and traffic.",
        "main": "Exploit the most promising boundary with reproducible curl/browser requests and follow the full state-changing chain.",
        "alt": "Test a disjoint vulnerability class and endpoint path, including auth logic, parser differentials, races, and client/server trust gaps.",
        "fallback": "Re-enumerate hidden routes and state transitions with a clean session; compare response/status/body deltas automatically.",
    },
    "forensics": {
        "recon": "Identify every file/container/layer and metadata timeline; hash inputs and work only on extracted copies.",
        "source": "Run format-specific analyzers for disk, memory, pcap, media, stego, or signals and preserve decoded intermediates.",
        "main": "Follow the strongest artifact chain, recursively extract/decode it, and validate the recovered payload against its format.",
        "alt": "Use an independent parser or modality-specific path to expose deleted, embedded, transformed, or covert data.",
        "fallback": "Return to magic bytes, entropy, offsets, channels, timestamps, and protocol objects to locate a missed layer.",
    },
    "cloud": {
        "recon": "Inventory IaC, identities, policies, trust relations, exposed services, and data paths without touching undeclared targets.",
        "source": "Compute effective permissions and trace identity-to-resource paths for policy, metadata, secret, and tenancy mistakes.",
        "main": "Reproduce the strongest authorized privilege or data-access chain with minimal scoped requests.",
        "alt": "Test a disjoint identity, policy, signing, storage, or service-confusion path.",
        "fallback": "Rebuild the effective access graph and inspect implicit defaults, condition keys, and cross-service trust.",
    },
    "misc": {
        "recon": "Classify the real domain from file signatures, protocols, encodings, runtime behavior, and challenge wording.",
        "source": "Create a small portfolio of distinct executable hypotheses and eliminate them with cheap discriminating tests.",
        "main": "Commit to the highest-yield surviving hypothesis and build an end-to-end solver.",
        "alt": "Pursue a different domain classification or representation with independent tooling.",
        "fallback": "Restart classification from raw bytes and I/O behavior; look for layered encodings, jails, games, hardware, or OSINT pivots.",
    },
}

_CATEGORY_VERIFICATION = {
    "pwn": "Verify by rerunning the exploit from a clean local process, then confirm the authorized remote I/O reaches the same flag path.",
    "rev": "Verify by feeding the recovered input to the original binary or an independent emulator and observing the acceptance path.",
    "crypto": "Verify with a supplied sample, round-trip, re-encryption, or an independently recomputed mathematical relation.",
    "web": "Verify with a clean reproducible session and the minimal request chain that reproduces the required state or flag response.",
    "forensics": "Verify the final artifact with an independent parser, decoder, checksum, magic value, or format-consistency check.",
    "cloud": "Verify the effective permission or data path using only minimal scoped requests against declared challenge resources.",
    "misc": "Verify by replaying the end-to-end solver from original inputs and checking the challenge's observable acceptance condition.",
}


@dataclass(frozen=True)
class RaceAttempt:
    attempt_id: str
    strategy_seed: str
    profile: AttemptProfile
    category: str = "misc"

    @property
    def strategy_instruction(self) -> str:
        phase = {"recon_fast": "recon", "recon_deep": "recon", "source_deep": "source",
                 "exploit_fast": "main", "exploit_main": "main", "exploit_alt": "alt",
                 "fallback": "fallback", "verifier": "main"}.get(self.profile.name, "main")
        strategy = _CATEGORY_STRATEGIES[self.category][phase]
        return (
            "This is a self-contained solve attempt: perform any prerequisite triage yourself; "
            "do not wait for another worker. " + strategy + " " + _CATEGORY_VERIFICATION[self.category]
        )


@dataclass(frozen=True)
class RacePlan:
    difficulty: str
    attempts: tuple[RaceAttempt, ...]

    @classmethod
    def for_score(
        cls,
        score: int,
        *,
        category: str = "misc",
        id_factory: Callable[[], str] | None = None,
        seed_factory: Callable[[], str] | None = None,
    ) -> "RacePlan":
        """Return a full plan; 401--499 is treated as medium to avoid an uncovered gap."""
        if score < 0:
            raise ValueError("score must be non-negative")
        difficulty = "easy" if score <= 200 else "medium" if score < 500 else "hard"
        make_id = id_factory or (lambda: uuid4().hex)
        make_seed = seed_factory or (lambda: token_hex(8))
        normalized = canonical_solver_category(category)
        return cls(
            difficulty=difficulty,
            attempts=tuple(
                RaceAttempt(make_id(), make_seed(), ATTEMPT_PROFILES[name], normalized)
                for name in _PROFILE_NAMES[difficulty]
            ),
        )

    @classmethod
    def build(
        cls,
        score: int,
        *,
        category: str = "misc",
        id_factory: Callable[[], str] | None = None,
        seed_factory: Callable[[], str] | None = None,
    ) -> "RacePlan":
        return cls.for_score(score, category=category, id_factory=id_factory, seed_factory=seed_factory)
