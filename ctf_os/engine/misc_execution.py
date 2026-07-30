"""Strict operator plan for the executable Misc transform hot path.

The JSON document parsed here contains locators only.  The challenge engine
resolves every locator through the challenge sandbox, snapshots the resolved
regular file, and replaces the locator with a full SHA-256 binding before any
tool is executed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath
from typing import Mapping

from ctf_os.engine.misc_transform import (
    MISC_TRANSFORM_MAX_SOURCES,
    MISC_TRANSFORM_MAX_STEPS,
)


MISC_EXECUTION_SPEC_SCHEMA_VERSION = 1
MISC_EXECUTION_MAX_SPEC_BYTES = 128 * 1024
MISC_EXECUTION_RUNTIME = "/usr/bin/python3"
MISC_EXECUTION_TRANSFORM_INTERFACE = (
    "/usr/bin/python3 TOOL INPUT...; exact output bytes on stdout; "
    "no stdout diagnostics"
)
MISC_EXECUTION_VERIFIER_INTERFACE = (
    "/usr/bin/python3 VERIFIER CANDIDATE ORIGINAL_SOURCE...; "
    "exit 0 accepts; "
    "stdout must be empty"
)

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")


class MiscExecutionSpecError(ValueError):
    """Stable rejection of an unsafe or ambiguous operator plan."""


@dataclass(frozen=True, slots=True)
class MiscExecutionSource:
    source_id: str
    locator: str


@dataclass(frozen=True, slots=True)
class MiscExecutionStep:
    step_id: str
    tool_locator: str
    parent_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MiscExecutionVerifier:
    verifier_id: str
    tool_locator: str
    oracle_id: str


@dataclass(frozen=True, slots=True)
class MiscExecutionSpec:
    sources: tuple[MiscExecutionSource, ...]
    steps: tuple[MiscExecutionStep, ...]
    terminal_step_id: str
    verifier: MiscExecutionVerifier


@dataclass(frozen=True, slots=True)
class MiscExecutionDagSpec:
    """Builder-visible transform graph without an oracle implementation."""

    sources: tuple[MiscExecutionSource, ...]
    steps: tuple[MiscExecutionStep, ...]
    terminal_step_id: str


def _exact_keys(
    value: Mapping[str, object],
    expected: frozenset[str],
    label: str,
) -> None:
    if frozenset(value) != expected:
        raise MiscExecutionSpecError(f"{label} has unknown or missing fields")


def _safe_id(value: object, label: str) -> str:
    if type(value) is not str or _SAFE_ID.fullmatch(value) is None:
        raise MiscExecutionSpecError(f"{label} is not a safe identifier")
    return value


def _locator(value: object, label: str) -> str:
    if type(value) is not str:
        raise MiscExecutionSpecError(
            f"{label} is not a bounded relative locator"
        )
    relative = PurePosixPath(value)
    if (
        not value
        or "\x00" in value
        or "\\" in value
        or len(value.encode("utf-8")) > 4096
        or relative.is_absolute()
        or PureWindowsPath(value).is_absolute()
        or relative.as_posix() != value
    ):
        raise MiscExecutionSpecError(f"{label} is not a bounded relative locator")
    if any(
        part in {"", ".", ".."}
        or len(part.encode("utf-8")) > 255
        for part in relative.parts
    ):
        raise MiscExecutionSpecError(f"{label} is not a bounded relative locator")
    return value


def _parse_misc_execution_graph(
    value: Mapping[str, object],
    *,
    expected_keys: frozenset[str],
    label: str,
) -> tuple[
    tuple[MiscExecutionSource, ...],
    tuple[MiscExecutionStep, ...],
    str,
]:
    _exact_keys(value, expected_keys, label)
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"]
        != MISC_EXECUTION_SPEC_SCHEMA_VERSION
    ):
        raise MiscExecutionSpecError("unsupported Misc execution spec schema")
    raw_sources = value["sources"]
    raw_steps = value["steps"]
    if (
        type(raw_sources) is not list
        or not 1 <= len(raw_sources) <= MISC_TRANSFORM_MAX_SOURCES
        or type(raw_steps) is not list
        or not 1 <= len(raw_steps) <= MISC_TRANSFORM_MAX_STEPS
    ):
        raise MiscExecutionSpecError("Misc execution spec count is invalid")

    sources: list[MiscExecutionSource] = []
    for ordinal, raw in enumerate(raw_sources, start=1):
        if not isinstance(raw, Mapping):
            raise MiscExecutionSpecError(f"source {ordinal} must be an object")
        _exact_keys(raw, frozenset({"id", "locator"}), f"source {ordinal}")
        sources.append(
            MiscExecutionSource(
                source_id=_safe_id(raw["id"], f"source {ordinal} id"),
                locator=_locator(raw["locator"], f"source {ordinal} locator"),
            )
        )

    steps: list[MiscExecutionStep] = []
    for ordinal, raw in enumerate(raw_steps, start=1):
        if not isinstance(raw, Mapping):
            raise MiscExecutionSpecError(f"step {ordinal} must be an object")
        _exact_keys(
            raw,
            frozenset({"id", "tool_locator", "parents"}),
            f"step {ordinal}",
        )
        parents = raw["parents"]
        if (
            type(parents) is not list
            or not parents
            or len(parents) > MISC_TRANSFORM_MAX_SOURCES
        ):
            raise MiscExecutionSpecError(f"step {ordinal} parents are invalid")
        parent_ids = tuple(
            _safe_id(parent, f"step {ordinal} parent")
            for parent in parents
        )
        if len(set(parent_ids)) != len(parent_ids):
            raise MiscExecutionSpecError(f"step {ordinal} parents repeat")
        steps.append(
            MiscExecutionStep(
                step_id=_safe_id(raw["id"], f"step {ordinal} id"),
                tool_locator=_locator(
                    raw["tool_locator"],
                    f"step {ordinal} tool locator",
                ),
                parent_ids=parent_ids,
            )
        )

    terminal = _safe_id(value["terminal_step_id"], "terminal step id")
    ids = [item.source_id for item in sources]
    ids.extend(item.step_id for item in steps)
    if len(set(ids)) != len(ids):
        raise MiscExecutionSpecError("source and step ids must be unique")
    if terminal not in {item.step_id for item in steps}:
        raise MiscExecutionSpecError("terminal step is unknown")
    if len(
        {
            *(item.locator for item in sources),
            *(item.tool_locator for item in steps),
        }
    ) != len(sources) + len(steps):
        raise MiscExecutionSpecError("all source and tool locators must be unique")
    return tuple(sources), tuple(steps), terminal


def parse_misc_execution_dag_spec(value: object) -> MiscExecutionDagSpec:
    """Parse the exact Builder-visible v1 graph (no verifier or oracle)."""

    if not isinstance(value, Mapping):
        raise MiscExecutionSpecError("Misc execution spec must be an object")
    sources, steps, terminal = _parse_misc_execution_graph(
        value,
        expected_keys=frozenset(
            {
                "schema_version",
                "sources",
                "steps",
                "terminal_step_id",
            }
        ),
        label="Misc execution DAG spec",
    )
    return MiscExecutionDagSpec(
        sources=sources,
        steps=steps,
        terminal_step_id=terminal,
    )


def parse_misc_execution_spec(value: object) -> MiscExecutionSpec:
    """Parse the exact bounded v1 operator document."""

    if not isinstance(value, Mapping):
        raise MiscExecutionSpecError("Misc execution spec must be an object")
    sources, steps, terminal = _parse_misc_execution_graph(
        value,
        expected_keys=frozenset(
            {
                "schema_version",
                "sources",
                "steps",
                "terminal_step_id",
                "verifier",
            }
        ),
        label="Misc execution spec",
    )
    raw_verifier = value["verifier"]
    if not isinstance(raw_verifier, Mapping):
        raise MiscExecutionSpecError("Misc verifier must be an object")
    _exact_keys(
        raw_verifier,
        frozenset({"id", "tool_locator", "oracle_id"}),
        "verifier",
    )
    verifier = MiscExecutionVerifier(
        verifier_id=_safe_id(raw_verifier["id"], "verifier id"),
        tool_locator=_locator(
            raw_verifier["tool_locator"],
            "verifier tool locator",
        ),
        oracle_id=_safe_id(raw_verifier["oracle_id"], "oracle id"),
    )
    if len(
        {
            *(item.locator for item in sources),
            *(item.tool_locator for item in steps),
            verifier.tool_locator,
        }
    ) != len(sources) + len(steps) + 1:
        raise MiscExecutionSpecError("all source and tool locators must be unique")

    return MiscExecutionSpec(
        sources=sources,
        steps=steps,
        terminal_step_id=terminal,
        verifier=verifier,
    )


__all__ = [
    "MISC_EXECUTION_MAX_SPEC_BYTES",
    "MISC_EXECUTION_RUNTIME",
    "MISC_EXECUTION_SPEC_SCHEMA_VERSION",
    "MISC_EXECUTION_TRANSFORM_INTERFACE",
    "MISC_EXECUTION_VERIFIER_INTERFACE",
    "MiscExecutionDagSpec",
    "MiscExecutionSource",
    "MiscExecutionSpec",
    "MiscExecutionSpecError",
    "MiscExecutionStep",
    "MiscExecutionVerifier",
    "parse_misc_execution_dag_spec",
    "parse_misc_execution_spec",
]
