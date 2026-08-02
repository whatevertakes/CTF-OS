"""Minimal category adapters; they advise the engine but do not schedule work."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class ExperimentSpec:
    id: str
    purpose: str
    command_template: tuple[str, ...]
    expected_observation: str
    keep_condition: str
    drop_condition: str
    resource_class: str = "light"
    timeout_s: int = 120
    requires_network: bool = False


@dataclass(frozen=True, slots=True)
class ProgressMarker:
    key: str
    label: str
    evidence_required: str


@dataclass(frozen=True, slots=True)
class ProofPolicy:
    mode: str
    clean_repetitions: int
    remote_repetitions: int = 0
    trial_count: int = 0
    minimum_success_rate: float | None = None
    notes: str = ""


class CategoryAdapter(Protocol):
    name: str

    def initial_observations(self) -> tuple[ExperimentSpec, ...]: ...

    def progress_markers(self) -> tuple[ProgressMarker, ...]: ...

    def proof_policy(self, *, remote: bool = False) -> ProofPolicy: ...

    def failure_labels(self) -> tuple[str, ...]: ...

    def captain_guidance(self) -> str: ...


class GenericAdapter:
    name = "misc"

    def initial_observations(self) -> tuple[ExperimentSpec, ...]:
        return (
            ExperimentSpec(
                id="inventory",
                purpose="inventory the immutable challenge input",
                command_template=(
                    "find",
                    "/challenge",
                    "-maxdepth",
                    "2",
                    "-type",
                    "f",
                    "-printf",
                    "%P\\n",
                ),
                expected_observation="bounded list of challenge files",
                keep_condition="at least one relevant input is identified",
                drop_condition="input is empty or belongs to another challenge",
            ),
        )

    def progress_markers(self) -> tuple[ProgressMarker, ...]:
        return (
            ProgressMarker(
                "input_understood",
                "input format understood",
                "executed fact or exact source locator",
            ),
            ProgressMarker(
                "primitive_observed",
                "useful primitive observed",
                "run and artifact reference",
            ),
            ProgressMarker(
                "candidate_produced",
                "candidate output produced",
                "replayable command and raw output",
            ),
        )

    def proof_policy(self, *, remote: bool = False) -> ProofPolicy:
        return ProofPolicy(
            mode="deterministic",
            clean_repetitions=3,
            remote_repetitions=1 if remote else 0,
        )

    def failure_labels(self) -> tuple[str, ...]:
        return (
            "wrong_tool",
            "unsupported_format",
            "no_new_evidence",
            "non_reproducible",
        )

    def captain_guidance(self) -> str:
        return (
            "Maintain one active goal. Register an experiment before execution; "
            "keep raw output in files and cite exact artifact paths."
        )


def get_adapter(category: str) -> CategoryAdapter:
    normalized = category.strip().lower()
    if normalized in {
        "pwn",
        "binary",
        "binary exploitation",
        "binary-exploitation",
        "pwnable",
        "system hacking",
        "system-hacking",
    }:
        from .pwn import PwnAdapter

        return PwnAdapter()
    if normalized in {
        "rev",
        "re",
        "reversing",
        "reverse",
        "reverse engineering",
        "reverse-engineering",
    }:
        from .reversing import ReversingAdapter

        return ReversingAdapter()
    if normalized in {"crypto", "cryptography"}:
        from .crypto import CryptoAdapter

        return CryptoAdapter()
    if normalized in {
        "forensic",
        "forensics",
        "dfir",
        "digital forensics",
        "digital-forensics",
    }:
        from .forensics import ForensicsAdapter

        return ForensicsAdapter()
    if normalized in {
        "web",
        "web hacking",
        "web-hacking",
        "web security",
        "web-security",
    }:
        from .web import WebAdapter

        return WebAdapter()
    if normalized in {
        "misc",
        "miscellaneous",
        "steganography",
        "stego",
        "jail",
        "ppc",
        "custom-protocol",
    }:
        from .misc import MiscAdapter

        return MiscAdapter()
    return GenericAdapter()
