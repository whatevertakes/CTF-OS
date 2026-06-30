#!/usr/bin/env python3
"""Validate category reference digests and skill wiring."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - preflight requires PyYAML.
    yaml = None


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "references.yaml"
REQUIRED_CATEGORIES = (
    "common",
    "pwn",
    "web",
    "rev",
    "crypto",
    "forensics",
    "stego",
    "mobile",
    "malware",
    "web3",
    "cloud-container",
    "ai-ml",
    "hardware-rf-side-channel",
    "osint",
    "jail",
    "programming",
    "misc",
    "hybrid",
)
SKILL_DIGESTS = {
    "ctf-ai-ml": "docs/reference-digests/ai-ml.md",
    "ctf-cloud": "docs/reference-digests/cloud-container.md",
    "ctf-container": "docs/reference-digests/cloud-container.md",
    "ctf-crypto": "docs/reference-digests/crypto.md",
    "ctf-forensics": "docs/reference-digests/forensics.md",
    "ctf-hardware-rf": "docs/reference-digests/hardware-rf-side-channel.md",
    "ctf-hybrid-chain": "docs/reference-digests/hybrid.md",
    "ctf-jail": "docs/reference-digests/jail.md",
    "ctf-level3-orchestrator": "docs/reference-digests/common.md",
    "ctf-malware": "docs/reference-digests/malware.md",
    "ctf-misc": "docs/reference-digests/misc.md",
    "ctf-mobile": "docs/reference-digests/mobile.md",
    "ctf-osint": "docs/reference-digests/osint.md",
    "ctf-programming": "docs/reference-digests/programming.md",
    "ctf-pwn": "docs/reference-digests/pwn.md",
    "ctf-rev": "docs/reference-digests/rev.md",
    "ctf-side-channel": "docs/reference-digests/hardware-rf-side-channel.md",
    "ctf-stego": "docs/reference-digests/stego.md",
    "ctf-triage": "docs/reference-digests/common.md",
    "ctf-web": "docs/reference-digests/web.md",
    "ctf-web3": "docs/reference-digests/web3.md",
}
REQUIRED_SECTIONS = (
    "## Trusted Sources",
    "## CTF-Relevant Patterns",
    "## CWE/CVE Mapping",
    "## Canonical Papers And Deep Dives",
    "## When To Use",
    "## When Not To Use",
    "## Source Anchors",
)


def fail(message: str, code: int = 1) -> None:
    print(f"reference_digest_check: {message}", file=sys.stderr)
    raise SystemExit(code)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="reference manifest path")
    return parser.parse_args()


def load_manifest(path: Path) -> list[dict[str, Any]]:
    if yaml is None:
        fail("PyYAML is required", code=2)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        fail(f"cannot read manifest: {exc}", code=2)
    except yaml.YAMLError as exc:
        fail(f"invalid manifest YAML: {exc}", code=2)
    if not isinstance(data, dict) or not isinstance(data.get("references"), list):
        fail("manifest must contain references list", code=2)
    refs = []
    for raw in data["references"]:
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str):
            fail("manifest references must be objects with id", code=2)
        refs.append(raw)
    return refs


def reference_ids(refs: list[dict[str, Any]]) -> set[str]:
    return {str(ref["id"]) for ref in refs}


def digest_paths(refs: list[dict[str, Any]]) -> set[str]:
    paths: set[str] = set()
    for ref in refs:
        path = ref.get("digest_path")
        if isinstance(path, str):
            paths.add(path)
    return paths


def load_indexes() -> dict[str, set[str]]:
    indexes: dict[str, set[str]] = {}
    for category in REQUIRED_CATEGORIES:
        path = ROOT / "docs" / "reference-index" / f"{category}.json"
        if not path.is_file():
            fail(f"missing reference index: {path.relative_to(ROOT)}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            fail(f"invalid reference index JSON {path.relative_to(ROOT)}: {exc}", code=2)
        if not isinstance(data, dict) or data.get("category") != category:
            fail(f"reference index category mismatch: {path.relative_to(ROOT)}", code=2)
        entries = data.get("entries")
        if not isinstance(entries, list) or not entries:
            fail(f"reference index has no entries: {path.relative_to(ROOT)}", code=2)
        entry_ids = set()
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                fail(f"reference index has invalid entry: {path.relative_to(ROOT)}", code=2)
            entry_ids.add(entry["id"])
        indexes[category] = entry_ids
    return indexes


def validate_digest(path: Path, allowed_ids: set[str], indexes: dict[str, set[str]]) -> None:
    if not path.is_file():
        fail(f"missing digest: {path.relative_to(ROOT)}")
    text = path.read_text(encoding="utf-8")
    for section in REQUIRED_SECTIONS:
        if section not in text:
            fail(f"{path.relative_to(ROOT)} missing section: {section}")
    for match in re.finditer(r"`ref:([^`]+)`", text):
        ref_id = match.group(1)
        if ref_id not in allowed_ids:
            fail(f"{path.relative_to(ROOT)} references unknown manifest id: {ref_id}")
    for match in re.finditer(r"`idx:([^:`]+):([^`]+)`", text):
        category = match.group(1)
        entry_id = match.group(2)
        if category not in indexes:
            fail(f"{path.relative_to(ROOT)} references unknown index category: {category}")
        if entry_id not in indexes[category]:
            fail(f"{path.relative_to(ROOT)} references unknown index entry: idx:{category}:{entry_id}")


def validate_skill(skill_dir: str, digest: str) -> None:
    path = ROOT / "skills" / skill_dir / "SKILL.md"
    if not path.is_file():
        fail(f"missing skill file: {path.relative_to(ROOT)}")
    text = path.read_text(encoding="utf-8")
    needle = f"reference_digest:\n- `{digest}`"
    if needle not in text:
        fail(f"{path.relative_to(ROOT)} missing reference digest wiring: {digest}")


def main() -> int:
    args = parse_args()
    manifest = Path(args.manifest).expanduser()
    if not manifest.is_absolute():
        manifest = ROOT / manifest
    refs = load_manifest(manifest.resolve())
    ids = reference_ids(refs)
    indexes = load_indexes()
    paths = digest_paths(refs)
    paths.update(f"docs/reference-digests/{category}.md" for category in REQUIRED_CATEGORIES)
    for path_string in sorted(paths):
        path = ROOT / path_string
        try:
            path.resolve().relative_to(ROOT)
        except ValueError:
            fail(f"digest path escapes workspace: {path_string}", code=2)
        validate_digest(path, ids, indexes)
    for skill_dir, digest in sorted(SKILL_DIGESTS.items()):
        validate_skill(skill_dir, digest)
    print(f"reference_digest_check ok: digests={len(paths)} indexes={len(indexes)} skills={len(SKILL_DIGESTS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
