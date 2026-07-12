"""Declarative tool strategies and deterministic attempt bootstrap.

The registry is intentionally data driven.  A selected strategy changes the
profile, preflight, launch helpers, prompt-visible tools, artifacts and budget;
it is not merely a model hint.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Callable, Iterable, Mapping, Sequence


SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class ToolCapability:
    id: str
    executables: tuple[str, ...]
    required: bool = True
    version_args: tuple[str, ...] = ("--version",)


@dataclass(frozen=True, slots=True)
class CapabilityCheck:
    capability: str
    available: bool
    executable: str | None = None
    version: str | None = None
    reason: str = ""


@dataclass(frozen=True, slots=True)
class ResourceBudget:
    timeout_sec: int = 900
    cpus: float = 2.0
    memory: str = "4g"
    processes: int = 128
    network_requests: int = 0


@dataclass(frozen=True, slots=True)
class ArtifactContract:
    type: str
    glob: str
    required: bool = False
    content_type: str = "application/octet-stream"


@dataclass(frozen=True, slots=True)
class ProgressSignal:
    kind: str
    weight: float
    pattern: str | None = None


@dataclass(frozen=True, slots=True)
class ExecutionHarness:
    id: str
    launch_script: str
    collector_script: str
    replay_script: str | None = None


@dataclass(frozen=True, slots=True)
class ToolStrategySpec:
    id: str
    version: int
    categories: tuple[str, ...]
    subtypes: tuple[str, ...]
    phases: tuple[str, ...]
    profile: str
    image: str
    required_capabilities: tuple[ToolCapability, ...]
    optional_capabilities: tuple[ToolCapability, ...] = ()
    harness: ExecutionHarness = field(default_factory=lambda: ExecutionHarness("generic", "", ""))
    environment: Mapping[str, str] = field(default_factory=dict)
    work_layout: tuple[str, ...] = ("input", "scripts", "results", "transcripts")
    command_templates: tuple[str, ...] = ()
    exposed_tools: tuple[str, ...] = ()
    input_artifacts: tuple[ArtifactContract, ...] = ()
    output_artifacts: tuple[ArtifactContract, ...] = ()
    progress_signals: tuple[ProgressSignal, ...] = ()
    failure_signals: tuple[str, ...] = ()
    budget: ResourceBudget = field(default_factory=ResourceBudget)
    fallback_strategy: str | None = None
    escalation_conditions: tuple[str, ...] = ()
    cleanup_actions: tuple[str, ...] = ("terminate_process_group", "preserve_artifacts")
    security_restrictions: tuple[str, ...] = (
        "authorized_targets_only", "manifest_allowlist", "no_auto_submit",
        "work_and_artifacts_only", "redact_credentials",
    )

    def __post_init__(self) -> None:
        if self.version != SCHEMA_VERSION:
            raise ValueError(f"unsupported strategy schema version {self.version}")
        if not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", self.id):
            raise ValueError("strategy id must be a stable lower_snake_case identifier")
        if not 60 <= self.budget.timeout_sec <= 3600:
            raise ValueError("strategy timeout must be between 60 and 3600 seconds")


@dataclass(frozen=True, slots=True)
class HarnessBootstrapResult:
    strategy_id: str
    strategy_version: int
    profile: str
    image: str
    root: Path
    launch_script: Path
    collector_script: Path
    replay_script: Path | None
    manifest_path: Path
    capability_checks: tuple[CapabilityCheck, ...]
    degraded: bool
    fallback_strategy: str | None = None


class StrategyRegistry:
    def __init__(self, specs: Iterable[ToolStrategySpec] = ()) -> None:
        self._specs: dict[str, ToolStrategySpec] = {}
        for spec in specs:
            self.register(spec)

    def register(self, spec: ToolStrategySpec) -> None:
        if spec.id in self._specs:
            raise ValueError(f"duplicate strategy id: {spec.id}")
        self._specs[spec.id] = spec

    def get(self, strategy_id: str) -> ToolStrategySpec:
        try:
            return self._specs[strategy_id]
        except KeyError as exc:
            raise KeyError(f"unknown tool strategy: {strategy_id}") from exc

    def all(self) -> tuple[ToolStrategySpec, ...]:
        return tuple(self._specs[key] for key in sorted(self._specs))

    def select(self, *, category: str, subtype: str = "", phase: str = "") -> tuple[ToolStrategySpec, ...]:
        def matches(spec: ToolStrategySpec) -> bool:
            return (("*" in spec.categories or category in spec.categories)
                    and (not subtype or "*" in spec.subtypes or subtype in spec.subtypes)
                    and (not phase or "*" in spec.phases or phase in spec.phases))
        return tuple(spec for spec in self.all() if matches(spec))


class StrategyExecutor:
    """Materialize a selected harness and perform a real executable preflight."""

    def __init__(self, registry: StrategyRegistry | None = None) -> None:
        self.registry = registry or default_strategy_registry()

    def preflight(
        self, spec: ToolStrategySpec, *,
        which: Callable[[str], str | None] = shutil.which,
        version_runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] | None = None,
    ) -> tuple[CapabilityCheck, ...]:
        runner = version_runner or _version_runner
        checks: list[CapabilityCheck] = []
        for capability in (*spec.required_capabilities, *spec.optional_capabilities):
            executable = next((path for name in capability.executables if (path := which(name))), None)
            if executable is None:
                checks.append(CapabilityCheck(capability.id, False, reason="executable not found"))
                continue
            version = "available"
            try:
                result = runner((executable, *capability.version_args))
                text = (result.stdout or result.stderr or "available").splitlines()[0][:240]
                version = _redact(text)
            except (OSError, subprocess.SubprocessError, IndexError):
                version = "available (version probe failed)"
            checks.append(CapabilityCheck(capability.id, True, executable, version))
        return tuple(checks)

    def bootstrap(
        self, strategy_id: str, workdir: str | Path, *,
        capability_checks: tuple[CapabilityCheck, ...] | None = None,
        which: Callable[[str], str | None] = shutil.which,
    ) -> HarnessBootstrapResult:
        spec = self.registry.get(strategy_id)
        root = Path(workdir).resolve(strict=False)
        root.mkdir(parents=True, exist_ok=True)
        for name in spec.work_layout:
            directory = root / name
            directory.mkdir(parents=True, exist_ok=True)
            # Attempt staging is private; the container's unprivileged ctf UID
            # must be able to produce contracted outputs after broker import.
            directory.chmod(0o1777)
        checks = capability_checks if capability_checks is not None else self.preflight(spec, which=which)
        required_ids = {item.id for item in spec.required_capabilities}
        missing = tuple(item.capability for item in checks if item.capability in required_ids and not item.available)
        scripts = root / "scripts"
        launch = scripts / "launch.sh"
        collector = scripts / "collect.py"
        replay = scripts / "replay.sh" if spec.harness.replay_script is not None else None
        _write_executable(launch, spec.harness.launch_script)
        _write_text(collector, spec.harness.collector_script)
        if replay is not None:
            _write_executable(replay, spec.harness.replay_script or "")
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "strategy": {"id": spec.id, "version": spec.version},
            "profile": spec.profile, "image": spec.image,
            "environment": dict(spec.environment), "commands": list(spec.command_templates),
            "tools": list(spec.exposed_tools), "capabilities": [asdict(item) for item in checks],
            "artifacts": [asdict(item) for item in spec.output_artifacts],
            "progress_signals": [asdict(item) for item in spec.progress_signals],
            "budget": asdict(spec.budget), "missing_required": list(missing),
            "fallback": spec.fallback_strategy if missing else None,
            "security": list(spec.security_restrictions),
        }
        manifest_path = root / "strategy-manifest.json"
        _write_text(manifest_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        return HarnessBootstrapResult(
            spec.id, spec.version, spec.profile, spec.image, root, launch, collector,
            replay, manifest_path, checks, bool(missing), spec.fallback_strategy if missing else None,
        )


def _version_runner(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(argv), shell=False, text=True, capture_output=True, timeout=3, check=False)


def _write_text(path: Path, content: str) -> None:
    path.write_text(content.rstrip() + "\n", encoding="utf-8")


def _write_executable(path: Path, content: str) -> None:
    _write_text(path, content)
    path.chmod(0o700)


def _redact(value: str) -> str:
    value = re.sub(r"(?i)(token|secret|password|api[_-]?key)\s*[:=]\s*\S+", r"\1=<redacted>", value)
    return value[:240]


def _cap(capability: str, *executables: str, required: bool = True) -> ToolCapability:
    return ToolCapability(capability, tuple(executables), required)


_COLLECTOR = """#!/usr/bin/env python3
import hashlib, json, pathlib
root = pathlib.Path('/artifacts') if pathlib.Path('/artifacts').is_dir() else pathlib.Path('results')
items = []
for path in sorted(p for p in root.rglob('*') if p.is_file() and p.name != 'artifact-manifest.json'):
    data = path.read_bytes()
    items.append({'path': str(path), 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)})
(root / 'artifact-manifest.json').write_text(json.dumps({'schema_version': 1, 'artifacts': items}, sort_keys=True))
"""


def _spec(
    id: str, profile: str, required: tuple[ToolCapability, ...], *,
    optional: tuple[ToolCapability, ...] = (), categories: tuple[str, ...] = ("*",),
    subtypes: tuple[str, ...] = ("*",), commands: tuple[str, ...], tools: tuple[str, ...],
    launch: str, artifacts: tuple[ArtifactContract, ...], timeout: int = 900,
    fallback: str | None = "fast_recon", network: int = 0,
) -> ToolStrategySpec:
    return ToolStrategySpec(
        id=id, version=1, categories=categories, subtypes=subtypes, phases=("*",),
        profile=profile, image=f"ctf-os-{profile}:latest", required_capabilities=required,
        optional_capabilities=optional, harness=ExecutionHarness(id, launch, _COLLECTOR,
            "#!/bin/sh\nset -eu\nexec \"$(dirname \"$0\")/launch.sh\" \"$@\"") ,
        command_templates=commands, exposed_tools=tools, output_artifacts=artifacts,
        progress_signals=(ProgressSignal("artifact_created", 1.0), ProgressSignal("primitive_acquired", 3.0),
                          ProgressSignal("hypothesis_eliminated", 0.5)),
        budget=ResourceBudget(timeout, 2.0, "4g", 128, network), fallback_strategy=fallback,
        escalation_conditions=("missing_required_capability", "budget_exhausted", "semantic_plateau"),
    )


def default_strategy_registry() -> StrategyRegistry:
    """Return the built-in registry. New strategies register without engine edits."""
    shell = "#!/bin/sh\nset -eu\nmkdir -p /work/results /artifacts\n"
    specs = (
        _spec("fast_recon", "base", (_cap("file", "file"), _cap("binutils", "readelf", "objdump")),
              optional=(_cap("checksec", "checksec", required=False), _cap("entropy", "binwalk", required=False)),
              commands=("./ctf-exec file /workspace/*", "./ctf-exec readelf -hW /workspace/<binary>", "./ctf-exec strings -a /workspace/<file>"),
              tools=("file", "strings", "readelf", "objdump", "nm", "checksec", "binwalk"),
              launch=shell + "file /workspace/* > /artifacts/file.txt 2>&1 || true\npython3 /work/scripts/collect.py\n",
              artifacts=(ArtifactContract("recon_manifest", "artifact-manifest.json", True, "application/json"),), timeout=300, fallback=None),
        _spec("exploit_build", "pwn", (_cap("python", "python3"), _cap("pwntools", "pwn"), _cap("patchelf", "patchelf")),
              optional=(_cap("pwninit", "pwninit", required=False), _cap("ropgadget", "ROPgadget", required=False)), categories=("pwn", "*"),
              commands=("./ctf-exec python3 /work/scripts/exploit.py --local", "./ctf-exec pwninit --bin /workspace/chall", "./ctf-exec patchelf --print-interpreter /workspace/chall"),
              tools=("python3", "pwntools", "pwninit", "patchelf", "ROPgadget"), launch=shell + "test -f /work/scripts/exploit.py || printf '%s\n' '#!/usr/bin/env python3' 'from pwn import *' > /work/scripts/exploit.py\npython3 /work/scripts/collect.py\n",
              artifacts=(ArtifactContract("exploit", "scripts/exploit.py", True, "text/x-python"), ArtifactContract("transcript", "transcripts/*")), timeout=1200, fallback="dynamic_analysis", network=200),
        _spec("dynamic_analysis", "pwn", (_cap("gdb", "gdb", "gdb-multiarch"), _cap("file", "file")),
              optional=(_cap("pwndbg_or_gef", "pwndbg", "gef", required=False),), categories=("pwn", "rev", "*"),
              commands=("./ctf-exec gdb -q -batch -x /work/scripts/debug.gdb /workspace/<binary>", "./ctf-exec /workspace/<binary>"),
              tools=("gdb", "gdb-multiarch", "strace", "ltrace"), launch=shell + "printf 'set pagination off\\ninfo files\\ninfo proc mappings\\ninfo registers\\nbt full\\n' > /work/scripts/debug.gdb\npython3 /work/scripts/collect.py\n",
              artifacts=(ArtifactContract("crash_signature", "results/crash.json", False, "application/json"), ArtifactContract("backtrace", "results/backtrace.txt")), timeout=900),
        _spec("symbolic_math", "crypto", (_cap("python", "python3"), _cap("z3", "z3")), optional=(_cap("sage", "sage", required=False),), categories=("crypto", "rev", "misc", "*"),
              commands=("./ctf-exec python3 /work/scripts/solve.py", "./ctf-exec sage /work/scripts/solve.sage"), tools=("python3", "z3", "sage", "sympy"),
              launch=shell + "test -f /work/scripts/solve.py || printf '%s\n' 'from z3 import *' 's=Solver()' 'print(s.check())' > /work/scripts/solve.py\npython3 /work/scripts/collect.py\n",
              artifacts=(ArtifactContract("solver_result", "results/solver-result.json", True, "application/json"), ArtifactContract("solution", "results/solution.*")), timeout=1200, fallback="deep_analysis"),
        _spec("protocol_replay", "web", (_cap("python", "python3"), _cap("curl", "curl")), optional=(_cap("tshark", "tshark", required=False),), categories=("web", "pwn", "misc", "*"),
              commands=("./ctf-exec python3 /work/scripts/replay.py --seed <seed>", "./ctf-exec curl --config /work/input/request.curl"), tools=("curl", "python3", "websockets", "tshark", "socat"),
              launch=shell + "test -f /work/scripts/replay.py || printf '%s\n' '#!/usr/bin/env python3' 'import json; print(json.dumps({\"frames\": []}))' > /work/scripts/replay.py\npython3 /work/scripts/collect.py\n",
              artifacts=(ArtifactContract("protocol_transcript", "transcripts/session.jsonl", True, "application/jsonl"), ArtifactContract("pcap", "transcripts/*.pcap")), timeout=900, network=300),
        _spec("artifact_recovery", "forensics", (_cap("file", "file"), _cap("archive", "unzip", "tar")), optional=(_cap("carving", "foremost", "binwalk", required=False),), categories=("forensics", "rev", "misc", "*"),
              commands=("./ctf-exec binwalk -Me /workspace/<file>", "./ctf-exec foremost -i /workspace/<image> -o /work/results/carved"), tools=("file", "binwalk", "foremost", "testdisk", "exiftool", "strings"),
              launch=shell + "find /workspace -type f -exec file '{}' ';' > /artifacts/recovery.txt\npython3 /work/scripts/collect.py\n",
              artifacts=(ArtifactContract("recovery_manifest", "artifact-manifest.json", True, "application/json"), ArtifactContract("recovered_file", "results/**/*")), timeout=900),
        _spec("deep_analysis", "reversing", (_cap("file", "file"), _cap("binutils", "objdump", "readelf")), optional=(_cap("radare2", "r2", required=False),),
              commands=("./ctf-exec r2 -Aqc afl /workspace/<binary>", "./ctf-exec objdump -d /workspace/<binary>"), tools=("r2", "objdump", "readelf", "angr"), launch=shell + "python3 /work/scripts/collect.py\n",
              artifacts=(ArtifactContract("analysis", "results/*"),), timeout=1200),
        _spec("independent_validation", "base", (_cap("python", "python3"),), commands=("./ctf-exec /work/scripts/replay.sh --candidate ...",), tools=("python3", "sha256sum"), launch=shell + "python3 /work/scripts/collect.py\n", artifacts=(ArtifactContract("verification_proof", "results/proof.json", True, "application/json"),), timeout=300, fallback=None),
        _spec("browser_automation", "browser", (_cap("python", "python3"), _cap("chromium", "chromium", "chromium-browser")), optional=(_cap("playwright", "playwright", required=False),), categories=("web", "osint", "*"), commands=("./ctf-exec python3 /work/scripts/browser.py" ,), tools=("playwright", "chromium"), launch=shell + "python3 /work/scripts/collect.py\n", artifacts=(ArtifactContract("screenshot", "results/*.png"), ArtifactContract("dom", "results/*.html")), timeout=900, fallback="protocol_replay", network=200),
        _spec("cloud_analysis", "cloud", (_cap("jq", "jq"), _cap("terraform", "terraform")), optional=(_cap("aws", "aws", required=False), _cap("gcloud", "gcloud", required=False), _cap("azure", "az", required=False), _cap("kubectl", "kubectl", required=False)), categories=("cloud", "*"), commands=("./ctf-exec terraform show -json", "./ctf-exec jq . /workspace/config.json"), tools=("aws", "gcloud", "az", "terraform", "kubectl", "helm", "jq", "yq"), launch=shell + "python3 /work/scripts/collect.py\n", artifacts=(ArtifactContract("cloud_findings", "results/cloud.json", True, "application/json"),), timeout=900, fallback="fast_recon"),
        _spec("mobile_analysis", "mobile", (_cap("jadx", "jadx"), _cap("apktool", "apktool")), optional=(_cap("adb", "adb", required=False), _cap("frida", "frida", required=False)), categories=("mobile", "rev", "*"), commands=("./ctf-exec jadx -d /work/results/jadx /workspace/app.apk", "./ctf-exec apktool d -o /work/results/apktool /workspace/app.apk"), tools=("jadx", "apktool", "adb", "frida", "objection"), launch=shell + "python3 /work/scripts/collect.py\n", artifacts=(ArtifactContract("android_manifest", "results/**/AndroidManifest.xml", True),), timeout=1200, fallback="artifact_recovery"),
        _spec("windows_analysis", "windows", (_cap("pefile", "python3"), _cap("wine", "wine")), optional=(_cap("dotnet", "dotnet", required=False),), categories=("pwn", "rev", "windows", "*"), commands=("./ctf-exec python3 -m pefile /workspace/chall.exe", "./ctf-exec wine /workspace/chall.exe"), tools=("wine", "pefile", "dotnet", "objdump"), launch=shell + "python3 /work/scripts/collect.py\n", artifacts=(ArtifactContract("pe_analysis", "results/pe.json", True, "application/json"),), timeout=900, fallback="deep_analysis"),
        _spec("password_cracking", "password", (_cap("hashcat_or_john", "hashcat", "john"),), categories=("password", "forensics", "misc", "*"), commands=("./ctf-exec hashcat --show /workspace/hashes", "./ctf-exec john --show /workspace/hashes"), tools=("hashcat", "john"), launch=shell + "python3 /work/scripts/collect.py\n", artifacts=(ArtifactContract("cracked_credentials", "results/cracked.json", True, "application/json"),), timeout=1800, fallback="fast_recon"),
        _spec("osint_collection", "osint", (_cap("curl", "curl"), _cap("metadata", "exiftool")), optional=(_cap("browser", "chromium", required=False),), categories=("osint", "misc", "*"), commands=("./ctf-exec exiftool -json /workspace/evidence",), tools=("curl", "exiftool", "chromium"), launch=shell + "python3 /work/scripts/collect.py\n", artifacts=(ArtifactContract("osint_provenance", "results/sources.json", True, "application/json"),), timeout=900, fallback="fast_recon", network=100),
    )
    return StrategyRegistry(specs)
