from __future__ import annotations

from ctf_os.contracts.rev_inventory_v2 import (
    REV_INVENTORY_V2_SEED_COMMAND_TEMPLATE,
    REV_INVENTORY_V2_SEED_DROP_CONDITION,
    REV_INVENTORY_V2_SEED_EXPECTED_OBSERVATION,
    REV_INVENTORY_V2_SEED_KEEP_CONDITION,
    REV_INVENTORY_V2_SEED_PURPOSE,
    REV_INVENTORY_V2_SEED_RESOURCE_CLASS,
    REV_INVENTORY_V2_SEED_TEMPLATE_ID,
    REV_INVENTORY_V2_SEED_TIMEOUT_SECONDS,
)

from .base import ExperimentSpec, GenericAdapter, ProgressMarker, ProofPolicy


class ReversingAdapter(GenericAdapter):
    name = "reversing"

    def initial_observations(self) -> tuple[ExperimentSpec, ...]:
        return (
            ExperimentSpec(
                REV_INVENTORY_V2_SEED_TEMPLATE_ID,
                REV_INVENTORY_V2_SEED_PURPOSE,
                REV_INVENTORY_V2_SEED_COMMAND_TEMPLATE,
                REV_INVENTORY_V2_SEED_EXPECTED_OBSERVATION,
                REV_INVENTORY_V2_SEED_KEEP_CONDITION,
                REV_INVENTORY_V2_SEED_DROP_CONDITION,
                REV_INVENTORY_V2_SEED_RESOURCE_CLASS,
                REV_INVENTORY_V2_SEED_TIMEOUT_SECONDS,
            ),
            ExperimentSpec(
                "assembly_observation",
                "collect independent disassembly and symbols",
                ("objdump", "-d", "{primary}"),
                "function and branch locators in raw output",
                "candidate validation logic is localized",
                "format is unsupported",
                "standard",
            ),
            ExperimentSpec(
                "decompiler_observation",
                "collect an independent decompiler view",
                ("ghidra-decompile", "{primary}"),
                "decompiled functions with locators",
                "logic agrees with execution or assembly",
                "decompiler output is missing or contradictory",
                "heavy",
                900,
            ),
            ExperimentSpec(
                "dynamic_observation",
                "observe actual executed validation path",
                ("ctfwrap", "--", "{primary}"),
                "runtime trace or input/output behavior",
                "executed path confirms a static hypothesis",
                "anti-debug or packer invalidates the view",
                "standard",
            ),
        )

    def progress_markers(self) -> tuple[ProgressMarker, ...]:
        return tuple(
            ProgressMarker(key, label, "function/offset/xref plus run reference")
            for key, label in (
                ("entry_located", "relevant entry located"),
                ("validation_found", "validation routine found"),
                ("logic_modeled", "algorithm modeled"),
                ("solver_works", "solver works on the binary"),
                ("keygen_generalizes", "solver generalizes across test cases"),
            )
        )

    def proof_policy(self, *, remote: bool = False) -> ProofPolicy:
        return ProofPolicy(
            mode="deterministic",
            clean_repetitions=3,
            notes="run an executable solver/keygen against multiple cases",
        )

    def failure_labels(self) -> tuple[str, ...]:
        return (
            "decompiler_decoy",
            "dead_code",
            "packed_view",
            "anti_debug",
            "hardcoded_candidate",
        )

    def captain_guidance(self) -> str:
        return (
            "Decompiler, assembly, and dynamic trace are independent views. On "
            "conflict prefer assembly plus executed behavior. Produce a runnable "
            "solver or keygen, not only an explanation."
        )
