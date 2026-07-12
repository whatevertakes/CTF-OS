"""Actual, redacted capability probes grouped by tactical profile."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import shutil
from typing import Callable

from .tactical_engine.strategies import StrategyExecutor, default_strategy_registry


@dataclass(frozen=True, slots=True)
class ProfileCapabilityReport:
    profile: str
    strategies: tuple[str, ...]
    checks: tuple[dict[str, object], ...]
    missing_required: tuple[str, ...]
    degraded: bool
    gpu: bool
    gui: bool
    browser: bool
    container: bool


def capability_reports(*, which: Callable[[str], str | None] = shutil.which) -> tuple[ProfileCapabilityReport, ...]:
    registry = default_strategy_registry()
    executor = StrategyExecutor(registry)
    profiles: dict[str, list] = {}
    for spec in registry.all():
        profiles.setdefault(spec.profile, []).append(spec)
    reports: list[ProfileCapabilityReport] = []
    for profile, specs in sorted(profiles.items()):
        seen: dict[str, dict[str, object]] = {}
        required: set[str] = set()
        for spec in specs:
            required.update(item.id for item in spec.required_capabilities)
            for check in executor.preflight(spec, which=which):
                existing = seen.get(check.capability)
                payload = asdict(check)
                if existing is None or (not existing["available"] and check.available):
                    seen[check.capability] = payload
        missing = tuple(sorted(item for item in required if not seen.get(item, {}).get("available")))
        reports.append(ProfileCapabilityReport(
            profile, tuple(sorted(spec.id for spec in specs)), tuple(seen[key] for key in sorted(seen)),
            missing, bool(missing), which("nvidia-smi") is not None, bool(which("xvfb-run")),
            any(item in seen and bool(seen[item]["available"]) for item in ("chromium", "browser")),
            which("docker") is not None,
        ))
    return tuple(reports)


def render_capabilities(*, json_output: bool = False) -> str:
    reports = capability_reports()
    if json_output:
        return json.dumps([asdict(item) for item in reports], indent=2, sort_keys=True)
    lines: list[str] = []
    for report in reports:
        state = "DEGRADED" if report.degraded else "OK"
        lines.append(f"{state} {report.profile}: strategies={','.join(report.strategies)}")
        for check in report.checks:
            version = check.get("version") or check.get("reason") or "unknown"
            lines.append(f"  {'OK' if check['available'] else 'MISS'} {check['capability']}: {version}")
        lines.append(f"  runtime: gpu={report.gpu} gui={report.gui} browser={report.browser} container={report.container}")
    return "\n".join(lines)
