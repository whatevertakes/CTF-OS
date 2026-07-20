"""Challenge-local input supplied by the current Sol session."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re
import unicodedata
from typing import Any

from .categories import canonical_category
from .challenge import SelectionError, resolve_selector
from .contest import ChallengeSpec, ContestManifest, safe_name
from .workspace import atomic_json, challenge_root


SESSION_INPUT_NAME = "SESSION-INPUT.json"
SESSION_INPUT_SCHEMA_VERSION = 2
_PROFILES = frozenset({"standard", "large", "large-forensic"})


def parse_session_input(value: str) -> dict[str, Any]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError("--session-input-json must contain a JSON object") from exc
    if not isinstance(payload, dict):
        raise ValueError("--session-input-json must contain a JSON object")
    return _normalize(payload)


def save_session_input(repo: Path, manifest: ContestManifest, challenge: ChallengeSpec, packet: dict[str, Any]) -> Path:
    path = challenge_root(repo, manifest, challenge) / SESSION_INPUT_NAME
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f"session input path is unsafe: {path}")
    atomic_json(path, packet)
    return path


def resolve_session_challenge(
    repo: Path, manifest: ContestManifest, selector: str, packet: dict[str, Any] | None = None,
) -> ChallengeSpec:
    if packet is not None:
        existing = _matching_manifest_challenge(manifest, packet["category"], packet["name"])
        challenge = _challenge_from_packet(manifest, packet, existing)
        try:
            selected = resolve_selector((challenge,), selector)
        except SelectionError as exc:
            raise ValueError("session input category/name does not match the selected challenge") from exc
        save_session_input(repo, manifest, selected, {
            **packet, "resolved_input_profile": selected.input_profile,
        })
        return selected

    try:
        selected = resolve_selector(manifest.challenges, selector)
    except SelectionError:
        selected = None
    if selected is not None:
        path = challenge_root(repo, manifest, selected) / SESSION_INPUT_NAME
        return _challenge_from_packet(manifest, load_session_input(path), selected) if path.is_file() else selected

    sessions: list[ChallengeSpec] = []
    contest_output = repo / "output" / manifest.slug
    for path in sorted(contest_output.glob(f"*/*/{SESSION_INPUT_NAME}")):
        packet_value = load_session_input(path)
        challenge = _challenge_from_packet(manifest, packet_value, _matching_manifest_challenge(
            manifest, packet_value["category"], packet_value["name"],
        ))
        if challenge_root(repo, manifest, challenge) / SESSION_INPUT_NAME != path:
            raise ValueError(f"session input is stored outside its challenge workspace: {path}")
        sessions.append(challenge)
    return resolve_selector(tuple(sessions), selector)


def load_session_input(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"session input is missing or unsafe: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"session input is unreadable: {path}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") not in {1, SESSION_INPUT_SCHEMA_VERSION}:
        raise ValueError(f"session input schema is invalid: {path}")
    return _normalize(payload, legacy=payload.get("schema_version") == 1)


def session_input_fingerprint(path: Path) -> str | None:
    if not path.exists():
        return None
    packet = load_session_input(path)
    canonical = json.dumps(packet, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def session_source_paths(manifest: ContestManifest, challenge: ChallengeSpec) -> list[Path] | None:
    path = challenge_root(manifest.path.parents[2], manifest, challenge) / SESSION_INPUT_NAME
    if not path.is_file():
        return None
    packet = load_session_input(path)
    if packet["category"] != challenge.category or packet["name"] != challenge.name:
        raise ValueError("session input identity does not match the selected challenge")
    contest_root = manifest.path.parent.resolve()
    present = set(packet.get("present_fields", []))
    if "source_paths" not in present:
        return None
    if not packet["source_paths"]:
        return []
    sources: list[Path] = []
    for declared in packet["source_paths"]:
        candidate = Path(declared)
        candidate = candidate.resolve() if candidate.is_absolute() else (contest_root / candidate).resolve()
        try:
            candidate.relative_to(contest_root)
        except ValueError as exc:
            raise ValueError(f"session source path is outside the selected contest: {declared}") from exc
        if candidate.is_symlink() or not (candidate.is_file() or candidate.is_dir()):
            raise ValueError(f"session source path is missing or unsafe: {declared}")
        sources.append(candidate)
    return sorted(set(sources), key=lambda item: item.as_posix().casefold())


def _normalize(payload: dict[str, Any], *, legacy: bool = False) -> dict[str, Any]:
    allowed = {
        "schema_version", "category", "name", "description", "hint", "flag_format",
        "flag_pattern", "remotes", "source_paths", "input_profile",
        "present_fields", "resolved_input_profile",
    }
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ValueError(f"session input contains unsupported fields: {', '.join(unknown)}")
    category = canonical_category(_required_text(payload, "category"))
    name = unicodedata.normalize("NFKC", _required_text(payload, "name"))
    if name in {".", ".."} or any(character in name for character in "/\\\0"):
        raise ValueError("session input challenge name is unsafe")
    optional = {
        "description", "hint", "flag_format", "flag_pattern", "remotes",
        "source_paths", "input_profile",
    }
    if legacy:
        present = {
            key for key in optional
            if (
                (key == "input_profile" and payload.get(key) not in {None, "standard"})
                or (key in {"remotes", "source_paths"} and bool(payload.get(key)))
                or (key not in {"input_profile", "remotes", "source_paths"} and payload.get(key) is not None)
            )
        }
    elif isinstance(payload.get("present_fields"), list):
        present = {str(value) for value in payload["present_fields"]}
        if not present <= optional:
            raise ValueError("session input present_fields contains unsupported fields")
    else:
        present = {key for key in optional if key in payload}
    profile = None
    if "input_profile" in present:
        raw_profile = payload.get("input_profile")
        if not isinstance(raw_profile, str) or not raw_profile.strip():
            raise ValueError("session input input_profile must be a non-empty string")
        profile = raw_profile.strip().casefold().replace("_", "-")
        if profile not in _PROFILES:
            raise ValueError(f"session input input_profile is invalid: {profile}")
    remotes = _string_list(payload.get("remotes"), "remotes") if "remotes" in present else []
    sources = _string_list(payload.get("source_paths"), "source_paths") if "source_paths" in present else []
    resolved_profile = payload.get("resolved_input_profile")
    if resolved_profile is not None:
        if not isinstance(resolved_profile, str) or resolved_profile not in _PROFILES:
            raise ValueError("session input resolved_input_profile is invalid")
    return {
        "schema_version": SESSION_INPUT_SCHEMA_VERSION,
        "category": category, "name": name,
        "description": _optional_text(payload.get("description"), present="description" in present),
        "hint": _optional_text(payload.get("hint"), present="hint" in present),
        "flag_format": _optional_text(payload.get("flag_format"), present="flag_format" in present),
        "flag_pattern": _optional_text(payload.get("flag_pattern"), present="flag_pattern" in present),
        "remotes": remotes, "source_paths": sources, "input_profile": profile,
        "present_fields": sorted(present), "resolved_input_profile": resolved_profile,
    }


def _challenge_from_packet(
    manifest: ContestManifest, packet: dict[str, Any], existing: ChallengeSpec | None,
) -> ChallengeSpec:
    present = set(packet.get("present_fields", []))
    base = existing or ChallengeSpec(
        number=len(manifest.challenges) + 1,
        id=hashlib.sha256(json.dumps(
            [unicodedata.normalize("NFKC", manifest.name).casefold(), packet["category"], packet["name"].casefold()],
            ensure_ascii=False,
        ).encode()).hexdigest()[:16],
        category=packet["category"], name=packet["name"],
        workspace_name=safe_name(packet["name"], fallback="challenge"), score=None,
        description=None, hint=None, remotes=(), flag_format=manifest.flag_format,
        flag_pattern=manifest.flag_pattern, input_profile=manifest.input_profile, warnings=(),
    )
    flag_format = packet["flag_format"] if "flag_format" in present else base.flag_format
    if "flag_pattern" in present:
        pattern = packet["flag_pattern"]
    elif "flag_format" in present:
        pattern = None
    else:
        pattern = base.flag_pattern
    # Deterministic merge contract: changing flag_format while omitting
    # flag_pattern regenerates a pattern from the new format. Explicit null
    # clears either field, including the generated pattern when format is null.
    if pattern is None and flag_format and "flag_pattern" not in present:
        pattern = re.escape(flag_format.strip()).replace(re.escape("..."), r"[^}\r\n]+")
        pattern = rf"\A{pattern}\Z"
    return replace(
        base,
        description=packet["description"] if "description" in present else base.description,
        hint=packet["hint"] if "hint" in present else base.hint,
        remotes=tuple(packet["remotes"]) if "remotes" in present else base.remotes,
        flag_format=flag_format, flag_pattern=pattern,
        input_profile=packet["input_profile"] if "input_profile" in present else base.input_profile,
    )


def _matching_manifest_challenge(manifest: ContestManifest, category: str, name: str) -> ChallengeSpec | None:
    return next((item for item in manifest.challenges if item.category == category and item.name.casefold() == name.casefold()), None)


def _required_text(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"session input {key} must be a non-empty string")
    return value.strip()


def _optional_text(value: Any, *, present: bool) -> str | None:
    if not present or value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("session input text fields must be strings")
    if not value.strip():
        raise ValueError("session input text fields must not be empty strings")
    return value.strip()


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"session input {label} must be a list of non-empty strings")
    return [item.strip() for item in value]
