"""Subtype-specific planners producing executable strategy contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from .profiles import ProblemProfile


@dataclass(frozen=True, slots=True)
class TacticalContract:
    id: str
    hypothesis: str
    prerequisites: tuple[str, ...]
    strategy: str
    harness: str
    commands: tuple[str, ...]
    input_artifacts: tuple[str, ...]
    output_artifacts: tuple[str, ...]
    success_signals: tuple[str, ...]
    failure_signals: tuple[str, ...]
    transition_conditions: tuple[str, ...]
    depends_on: tuple[str, ...] = ()
    parallel_group: str | None = None
    cancellable: bool = True
    timeout_sec: int = 900
    estimated_cost: float = 1.0


@dataclass(frozen=True, slots=True)
class TacticalPlan:
    planner_id: str
    profile: ProblemProfile
    contracts: tuple[TacticalContract, ...]
    fallback_used: bool = False


Planner = Callable[[ProblemProfile], TacticalPlan]


class PlannerRegistry:
    def __init__(self) -> None:
        self._planners: dict[tuple[str, str], Planner] = {}

    def register(self, category: str, subtype: str, planner: Planner) -> None:
        key = (category, subtype)
        if key in self._planners:
            raise ValueError(f"duplicate planner: {category}.{subtype}")
        self._planners[key] = planner

    def has(self, category: str, subtype: str) -> bool:
        return (category, subtype) in self._planners

    def registered(self) -> tuple[str, ...]:
        return tuple(f"{category}.{subtype}" for category, subtype in sorted(self._planners))

    def plan(self, profile: ProblemProfile) -> TacticalPlan:
        planner = self._planners.get((profile.category, profile.subtype))
        if planner is None:
            return _generic_plan(profile)
        return planner(profile)


def _contract(profile: ProblemProfile, *, hypothesis: str, strategy: str, commands: tuple[str, ...],
              success: tuple[str, ...], failure: tuple[str, ...], transition: tuple[str, ...],
              inputs: tuple[str, ...] = (), outputs: tuple[str, ...] = (), timeout: int = 900,
              depends: tuple[str, ...] = (), group: str | None = None) -> TacticalContract:
    return TacticalContract(
        id=f"{profile.category}.{profile.subtype}:{strategy}", hypothesis=hypothesis,
        prerequisites=tuple(profile.constraints), strategy=strategy, harness=strategy,
        commands=commands, input_artifacts=inputs, output_artifacts=outputs,
        success_signals=success, failure_signals=failure, transition_conditions=transition,
        depends_on=depends, parallel_group=group, timeout_sec=timeout,
    )


def _standard(profile: ProblemProfile) -> TacticalPlan:
    contracts = tuple(_contract(
        profile, hypothesis=f"Validate {profile.subtype} with executable evidence", strategy=strategy,
        commands=(f"bootstrap:{strategy}",), success=("finding.created", "artifact.created", "primitive.acquired"),
        failure=("command.failed", "semantic_plateau"), transition=("new_evidence", "capability_missing", "budget_threshold"),
        outputs=("strategy_manifest",), timeout=300 if strategy == "fast_recon" else 900,
        group="initial" if len(profile.candidate_strategies) > 1 else None,
    ) for strategy in profile.candidate_strategies)
    return TacticalPlan(f"{profile.category}.{profile.subtype}", profile, contracts)


def _heap(profile: ProblemProfile) -> TacticalPlan:
    recon = _contract(profile, hypothesis="Determine glibc/loader, mitigations, allocation primitives and leak state",
        strategy="fast_recon", commands=("file/readelf/checksec target", "identify provided libc and loader", "extract allocator version"),
        success=("glibc_version", "allocation_primitive", "leak_kind"), failure=("binary_missing",),
        transition=("libc_leak=>exploit", "heap_crash=>dynamic"), outputs=("recon_manifest",), timeout=300, group="heap-triage")
    dynamic = _contract(profile, hypothesis="Map tcache/fastbin/unsorted state and acquire read/write or control-flow primitive",
        strategy="dynamic_analysis", commands=("gdb batch with allocation breakpoints", "replay identical heap transcript"),
        success=("heap_base", "libc_leak", "arbitrary_read", "arbitrary_write"), failure=("same_crash_cluster",),
        transition=("primitive_acquired=>exploit", "plateau=>change_allocator_hypothesis"), inputs=("recon_manifest",), outputs=("crash_signature", "heap_snapshot"), timeout=900, depends=(recon.id,))
    exploit = _contract(profile, hypothesis="Convert acquired allocator primitive into a reliable flag path",
        strategy="exploit_build", commands=("pwninit/patchelf", "pwntools local replay", "authorized remote replay"),
        success=("reliable_local_exploit", "flag_candidate"), failure=("retry_exhausted",),
        transition=("libc_leak", "control_flow_primitive"), inputs=("recon_manifest", "heap_snapshot", "libc_base"), outputs=("exploit", "transcript"), timeout=1200, depends=(dynamic.id,))
    return TacticalPlan("pwn.heap.glibc", profile, (recon, dynamic, exploit))


def _request_smuggling(profile: ProblemProfile) -> TacticalPlan:
    return TacticalPlan("web.request_smuggling", profile, (_contract(profile,
        hypothesis="A front-end/back-end CL/TE parsing differential creates response desynchronization",
        strategy="protocol_replay", commands=("baseline keep-alive replay", "CL.TE/TE.CL mutation matrix", "repeat with seeded victim request"),
        success=("response_desync", "backend_queue_poisoned"), failure=("all_parser_variants_equivalent",),
        transition=("desync=>stateful_exploitation", "no_desync=>alternate_web_planner"), outputs=("protocol_transcript", "mutation_matrix"), timeout=900),))


def _generic_plan(profile: ProblemProfile) -> TacticalPlan:
    contract = _contract(profile, hypothesis="Resolve the unknown subtype using discriminating local evidence",
                         strategy="fast_recon", commands=("collect structured file/protocol metadata",),
                         success=("classification.updated",), failure=("no_new_evidence",),
                         transition=("classification_changed=>specialized_planner",), outputs=("recon_manifest",), timeout=300)
    return TacticalPlan("generic.unknown", profile, (contract,), True)


def default_planner_registry() -> PlannerRegistry:
    registry = PlannerRegistry()
    special: dict[tuple[str, str], Planner] = {
        ("pwn", "heap.glibc"): _heap,
        ("web", "request_smuggling"): _request_smuggling,
    }
    supported = {
        "pwn": ("stack_overflow", "rop", "shellcode", "format_string", "heap", "heap.glibc",
                 "heap.custom_allocator", "seccomp", "race_condition", "kernel", "sandbox_escape",
                 "windows", "protocol_state_machine"),
        "web": ("sql_injection", "ssrf", "request_smuggling", "deserialization", "cache_poisoning",
                 "oauth_oidc", "jwt", "ssti", "xxe", "path_traversal", "auth_logic",
                 "race_condition", "browser_client", "websocket", "graphql", "upload_parser_confusion"),
        "rev": ("native_elf", "packed_obfuscated", "windows_pe", "dotnet", "java_jar", "android_apk",
                "bytecode_vm", "anti_debug", "symbolic_execution", "firmware_embedded"),
        "crypto": ("modular_arithmetic", "rsa", "ecc", "lattice", "prng", "hash_mac_misuse",
                   "padding_oracle", "custom_cipher", "constraint_solving", "protocol_crypto"),
        "forensics": ("pcap", "disk_image", "memory_dump", "document_media_stego", "archive_polyglot",
                      "log_timeline", "firmware", "mobile_artifact", "cloud_artifact"),
        "cloud": ("configuration",), "mobile": ("android_static",),
        "password": ("hash_cracking",), "osint": ("web_collection",),
        "hardware": ("embedded",), "misc": ("protocol",),
    }
    for category, subtypes in supported.items():
        for subtype in subtypes:
            registry.register(category, subtype, special.get((category, subtype), _standard))
    return registry
