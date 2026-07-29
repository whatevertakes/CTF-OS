"""Small, explicit configuration layer for CTF-OS.

The engine deliberately keeps configuration in one TOML file.  Logical worker
widths and the provider call limit are separate values: a provider limit may
delay a call, but it never changes the roles in a wave.
"""

from __future__ import annotations

import math
import os
import re
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ctf_os.codex.contracts import ReasoningEffort
from ctf_os.images import (
    ImageReferenceError,
    validate_image_digest,
    validate_image_name,
)
from ctf_os.models import MAX_EXPERIMENT_TIMEOUT_SECONDS
from ctf_os.remote_limiter import (
    DEFAULT_MIN_INTERVAL_SECONDS,
    MAX_MIN_INTERVAL_SECONDS,
)

CONFIG_DIRECTORY = ".ctfos"
CONFIG_FILE = "engine.toml"


class ConfigError(ValueError):
    """Raised when ``engine.toml`` contains an unsafe or invalid value."""


@dataclass(frozen=True, slots=True)
class ModelConfig:
    captain: str = "gpt-5.6-sol"
    recon: str = "gpt-5.6-terra"
    specialist: str = "gpt-5.6-terra"
    builder: str = "gpt-5.6-sol"
    falsifier: str = "gpt-5.6-sol"
    extractor: str = "gpt-5.6-luna"
    reproducer: str = "gpt-5.6-terra"
    validator: str = "gpt-5.6-sol"
    evidence_auditor: str = "gpt-5.6-luna"
    captain_effort: str = "ultra"
    worker_effort: str = "max"


@dataclass(frozen=True, slots=True)
class ResourceConfig:
    worker_slots_per_challenge: int = 3
    wave_width_discovery: int = 3
    wave_width_attack: int = 3
    wave_width_proof: int = 3
    provider_max_concurrent_calls: int = 4
    provider_wait_timeout_s: float = 900.0
    tool_cpu_budget: int = 8
    tool_memory_gib: int = 18
    max_standard_jobs: int = 2
    max_gpu_jobs: int = 1
    lease_wait_timeout_s: float = 300.0
    remote_command_min_interval_s: float = DEFAULT_MIN_INTERVAL_SECONDS


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    image: str = "ctf-os:core"
    image_digest: str | None = None
    network_default: str = "none"
    flag_patterns: tuple[str, ...] = (
        r"(?i)\b(?:flag|ctf)\{[^{}\r\n]{1,512}\}",
        r"\b[A-Za-z0-9_]{2,32}\{[^{}\r\n]{1,512}\}",
    )
    flag_scan_max_bytes: int = 16 * 1024 * 1024
    work_tree_max_bytes: int = 16 * 1024 * 1024 * 1024
    command_timeout_s: int = 900
    wave_deadline_s: float = 1800.0


@dataclass(frozen=True, slots=True)
class EngineConfig:
    workspace_root: Path
    models: ModelConfig = field(default_factory=ModelConfig)
    resources: ResourceConfig = field(default_factory=ResourceConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)

    @property
    def state_root(self) -> Path:
        return self.workspace_root / CONFIG_DIRECTORY

    @property
    def incoming_root(self) -> Path:
        return self.workspace_root / "incoming"

    @property
    def config_path(self) -> Path:
        return self.state_root / CONFIG_FILE


def _section(document: dict[str, Any], name: str) -> dict[str, Any]:
    value = document.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{name}] must be a TOML table")
    return value


def _known_values(
    section: dict[str, Any], defaults: object, section_name: str
) -> dict[str, Any]:
    known = set(defaults.__dataclass_fields__)  # type: ignore[attr-defined]
    unknown = sorted(set(section) - known)
    if unknown:
        joined = ", ".join(unknown)
        raise ConfigError(f"unknown [{section_name}] setting(s): {joined}")
    return section


def _validate(config: EngineConfig) -> EngineConfig:
    models = config.models
    model_fields = (
        "captain",
        "recon",
        "specialist",
        "builder",
        "falsifier",
        "extractor",
        "reproducer",
        "validator",
        "evidence_auditor",
    )
    for name in model_fields:
        value = getattr(models, name)
        if not isinstance(value, str) or not value.strip():
            raise ConfigError(f"[models] {name} must be a non-empty string")
    allowed_efforts = {effort.value for effort in ReasoningEffort}
    for name in ("captain_effort", "worker_effort"):
        value = getattr(models, name)
        if not isinstance(value, str) or value not in allowed_efforts:
            raise ConfigError(
                f"[models] {name} must be one of "
                + ", ".join(sorted(allowed_efforts))
            )

    resources = config.resources
    positive_ints = (
        "worker_slots_per_challenge",
        "wave_width_discovery",
        "wave_width_attack",
        "wave_width_proof",
        "provider_max_concurrent_calls",
        "tool_cpu_budget",
        "tool_memory_gib",
        "max_standard_jobs",
        "max_gpu_jobs",
    )
    for name in positive_ints:
        value = getattr(resources, name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ConfigError(f"[resources] {name} must be a positive integer")
    for name in ("provider_wait_timeout_s", "lease_wait_timeout_s"):
        value = getattr(resources, name)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or value <= 0
        ):
            raise ConfigError(
                f"[resources] {name} must be finite and positive"
            )
    remote_interval = resources.remote_command_min_interval_s
    if (
        isinstance(remote_interval, bool)
        or not isinstance(remote_interval, (int, float))
        or not math.isfinite(float(remote_interval))
        or not 0 <= float(remote_interval) <= MAX_MIN_INTERVAL_SECONDS
    ):
        raise ConfigError(
            "[resources] remote_command_min_interval_s must be finite and "
            f"between 0 and {MAX_MIN_INTERVAL_SECONDS}"
        )
    logical_widths = (
        "worker_slots_per_challenge",
        "wave_width_discovery",
        "wave_width_attack",
        "wave_width_proof",
    )
    for name in logical_widths:
        if getattr(resources, name) != 3:
            raise ConfigError(
                f"[resources] {name} must remain 3; account/provider "
                "limits queue calls instead of changing logical roles"
            )

    runtime = config.runtime
    if runtime.network_default != "none":
        raise ConfigError(
            "[runtime] network_default must remain 'none'; use a "
            "challenge target allowlist for remote access"
        )
    try:
        validate_image_name(runtime.image)
    except ImageReferenceError as error:
        raise ConfigError(f"[runtime] {error}") from error
    if runtime.image_digest is not None:
        try:
            validate_image_digest(runtime.image_digest)
        except ImageReferenceError as error:
            raise ConfigError(f"[runtime] {error}") from error
    if not runtime.flag_patterns:
        raise ConfigError("[runtime] flag_patterns cannot be empty")
    for name in ("flag_scan_max_bytes", "work_tree_max_bytes"):
        value = getattr(runtime, name)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
        ):
            raise ConfigError(f"[runtime] {name} must be a positive integer")
    command_timeout = runtime.command_timeout_s
    if (
        isinstance(command_timeout, bool)
        or not isinstance(command_timeout, int)
        or not 1 <= command_timeout <= MAX_EXPERIMENT_TIMEOUT_SECONDS
    ):
        raise ConfigError(
            "[runtime] command_timeout_s must be an integer between 1 and "
            f"{MAX_EXPERIMENT_TIMEOUT_SECONDS}"
        )
    wave_deadline = runtime.wave_deadline_s
    if (
        isinstance(wave_deadline, bool)
        or not isinstance(wave_deadline, (int, float))
        or not math.isfinite(float(wave_deadline))
        or wave_deadline <= 0
    ):
        raise ConfigError(
            "[runtime] wave_deadline_s must be finite and positive"
        )
    return config


def load_config(workspace_root: Path) -> EngineConfig:
    """Load ``.ctfos/engine.toml``, falling back to safe defaults."""

    root = workspace_root.expanduser().resolve()
    config = EngineConfig(workspace_root=root)
    path = config.config_path
    if path.exists():
        try:
            document = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
            raise ConfigError(f"cannot read {path}: {error}") from error
        if not isinstance(document, dict):
            raise ConfigError("engine.toml must contain a TOML document")
        allowed_sections = {"models", "resources", "runtime"}
        unknown_sections = sorted(set(document) - allowed_sections)
        if unknown_sections:
            raise ConfigError(
                "unknown engine.toml section(s): "
                + ", ".join(unknown_sections)
            )

        model_values = _known_values(
            _section(document, "models"), config.models, "models"
        )
        resource_values = _known_values(
            _section(document, "resources"), config.resources, "resources"
        )
        runtime_values = _known_values(
            _section(document, "runtime"), config.runtime, "runtime"
        )
        if "flag_patterns" in runtime_values:
            patterns = runtime_values["flag_patterns"]
            if not isinstance(patterns, list) or not all(
                isinstance(item, str) and item for item in patterns
            ):
                raise ConfigError(
                    "[runtime] flag_patterns must be a non-empty string array"
                )
            runtime_values = {
                **runtime_values,
                "flag_patterns": tuple(patterns),
            }
        try:
            config = replace(
                config,
                models=replace(config.models, **model_values),
                resources=replace(config.resources, **resource_values),
                runtime=replace(config.runtime, **runtime_values),
            )
        except TypeError as error:
            raise ConfigError(f"invalid engine.toml value: {error}") from error

    limit_override = os.environ.get("CTFOS_MODEL_CONCURRENCY")
    if limit_override is not None:
        try:
            limit = int(limit_override)
        except ValueError as error:
            raise ConfigError(
                "CTFOS_MODEL_CONCURRENCY must be a positive integer"
            ) from error
        config = replace(
            config,
            resources=replace(
                config.resources, provider_max_concurrent_calls=limit
            ),
        )
    return _validate(config)


def default_config_text() -> str:
    """Return the commented baseline written by ``ctfos init``."""

    return """# CTF-OS local engine configuration.
# Logical wave width is independent of provider call concurrency.
[models]
captain = "gpt-5.6-sol"
recon = "gpt-5.6-terra"
specialist = "gpt-5.6-terra"
builder = "gpt-5.6-sol"
falsifier = "gpt-5.6-sol"
extractor = "gpt-5.6-luna"
reproducer = "gpt-5.6-terra"
validator = "gpt-5.6-sol"
evidence_auditor = "gpt-5.6-luna"
captain_effort = "ultra"
worker_effort = "max"

[resources]
worker_slots_per_challenge = 3
wave_width_discovery = 3
wave_width_attack = 3
wave_width_proof = 3
# Calls wait here when the account/provider limit is reached. Roles are not
# removed and waves are not narrowed.
provider_max_concurrent_calls = 4
provider_wait_timeout_s = 900.0
tool_cpu_budget = 8
tool_memory_gib = 18
max_standard_jobs = 2
max_gpu_jobs = 1
lease_wait_timeout_s = 300.0
# Spaces CTF-OS command starts targeting the same normalized hostname.
# This is not an HTTP request limiter; requests inside one command require an
# external restricted proxy/firewall. Set 0 to explicitly disable spacing.
remote_command_min_interval_s = 1.0

[runtime]
image = "ctf-os:core"
# Optional exact local Docker image ID. Run `ctfos pin-image` before a contest.
# image_digest = "sha256:<64 lowercase hex>"
network_default = "none"
flag_patterns = [
  '(?i)\\b(?:flag|ctf)\\{[^{}\\r\\n]{1,512}\\}',
  '\\b[A-Za-z0-9_]{2,32}\\{[^{}\\r\\n]{1,512}\\}',
]
flag_scan_max_bytes = 16777216
# Descriptor-anchored checks account /work before and after each command.
# This is not a live filesystem quota; a command can transiently exceed it.
work_tree_max_bytes = 17179869184
command_timeout_s = 900
wave_deadline_s = 1800.0
"""


_TABLE_HEADER = re.compile(r"^\s*\[([A-Za-z0-9_.-]+)\]\s*(?:#.*)?$")
_IMAGE_DIGEST_ASSIGNMENT = re.compile(r"^\s*image_digest\s*=")
_IMAGE_ASSIGNMENT = re.compile(r"^\s*image\s*=")


def set_runtime_image_digest(text: str, image_digest: str) -> str:
    """Replace or insert only ``[runtime].image_digest`` in valid TOML text."""

    digest = validate_image_digest(image_digest)
    try:
        document = tomllib.loads(text)
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ConfigError(f"cannot update invalid engine.toml: {error}") from error
    if not isinstance(document, dict):
        raise ConfigError("engine.toml must contain a TOML document")

    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines(keepends=True)
    runtime_start: int | None = None
    runtime_end = len(lines)
    for index, line in enumerate(lines):
        header = _TABLE_HEADER.fullmatch(line.rstrip("\r\n"))
        if header is None:
            continue
        if runtime_start is not None:
            runtime_end = index
            break
        if header.group(1) == "runtime":
            runtime_start = index

    assignment = f'image_digest = "{digest}"{newline}'
    if runtime_start is None:
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] += newline
        if lines and lines[-1].strip():
            lines.append(newline)
        lines.extend((f"[runtime]{newline}", assignment))
    else:
        digest_index: int | None = None
        image_index: int | None = None
        for index in range(runtime_start + 1, runtime_end):
            body = lines[index].rstrip("\r\n")
            if _IMAGE_DIGEST_ASSIGNMENT.match(body):
                digest_index = index
                break
            if _IMAGE_ASSIGNMENT.match(body):
                image_index = index
        if digest_index is not None:
            lines[digest_index] = assignment
        else:
            insert_at = (
                image_index + 1
                if image_index is not None
                else runtime_start + 1
            )
            if insert_at > 0 and not lines[insert_at - 1].endswith(("\n", "\r")):
                lines[insert_at - 1] += newline
            lines.insert(insert_at, assignment)

    updated = "".join(lines)
    try:
        updated_document = tomllib.loads(updated)
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(f"updated engine.toml is invalid: {error}") from error
    runtime = updated_document.get("runtime", {})
    if not isinstance(runtime, dict) or runtime.get("image_digest") != digest:
        raise ConfigError("updated engine.toml did not retain runtime.image_digest")
    return updated
