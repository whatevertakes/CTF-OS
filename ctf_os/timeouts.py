from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class TimeoutProfileError(ValueError):
    pass


RETAIN_BY_DEFAULT = frozenset({
    "decompile", "symbolic_slice", "fuzz_slice", "forensic_scan",
    "crypto_heavy", "cracking_slice", "ai_inference",
})


def retain_sandbox_on_timeout(profile: str | None, explicit: bool | None = None) -> bool:
    if explicit is not None:
        return explicit
    return bool(profile and profile in RETAIN_BY_DEFAULT)


def load_timeout_profiles(path: Path | None = None) -> dict[str, int]:
    source = path or Path(__file__).parent / "resources" / "timeout-profiles.yaml"
    if source.is_symlink() or not source.is_file():
        raise TimeoutProfileError("timeout profile resource is missing or unsafe")
    raw: Any = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TimeoutProfileError("timeout profile resource must be a mapping")
    result = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, int) or not 1 <= value <= 1800:
            raise TimeoutProfileError("timeout profiles must map names to 1..1800 seconds")
        result[key] = value
    return result


def timeout_seconds(profile: str) -> int:
    profiles = load_timeout_profiles()
    try:
        return profiles[profile]
    except KeyError as exc:
        raise TimeoutProfileError(f"unknown timeout profile {profile!r}; choose one of {', '.join(profiles)}") from exc
