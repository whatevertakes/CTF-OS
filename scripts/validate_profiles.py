#!/usr/bin/env python3
"""Static CI validation for profile definitions and strategy references."""
from pathlib import Path
import sys
import yaml

from ctf_os.tactical_engine.strategies import default_strategy_registry

root = Path(__file__).resolve().parents[1]
raw = yaml.safe_load((root / "sandbox/profiles.yaml").read_text())
if raw.get("schema_version") != 1 or not isinstance(raw.get("profiles"), dict):
    raise SystemExit("invalid sandbox profile schema")
profiles = raw["profiles"]
used = {item.profile for item in default_strategy_registry().all()}
missing = sorted(used - set(profiles))
if missing:
    raise SystemExit(f"missing strategy profiles: {', '.join(missing)}")
dockerfile = (root / "sandbox/Dockerfile.profiles").read_text()
missing_stages = sorted(profile for profile in profiles if profile != "base" and f" AS {profile}\n" not in dockerfile)
if missing_stages:
    raise SystemExit(f"missing Dockerfile stages: {', '.join(missing_stages)}")
print(f"validated {len(profiles)} profiles and {len(used)} strategy profile references")
