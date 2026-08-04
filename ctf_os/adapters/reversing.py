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


_REV_REGULAR_PRIMARY_PROBE = (
    "set -eu; target=$1; probe=$2; "
    "if [ -L \"$target\" ]; then "
    "printf 'ctfos_rev_probe=%s\\n' \"$probe\" >&2; "
    "printf '%s\\n' 'ctfos_rev_probe_error=symlink_primary_binding' >&2; "
    "exit 2; fi; "
    "if [ ! -f \"$target\" ]; then "
    "printf 'ctfos_rev_probe=%s\\n' \"$probe\"; "
    "printf '%s\\n' 'ctfos_rev_probe_status=skipped' "
    "'ctfos_rev_probe_reason=no_regular_primary_binding'; "
    "exit 0; fi; "
    "exec ghidra-decompile \"$target\""
)


_REV_ELF_PRIMARY_PROBE = (
    "set -eu; target=$1; probe=$2; work_root=${3:-/work}; "
    "if [ -L \"$target\" ]; then "
    "printf 'ctfos_rev_probe=%s\\n' \"$probe\" >&2; "
    "printf '%s\\n' 'ctfos_rev_probe_error=symlink_primary_binding' >&2; "
    "exit 2; fi; "
    "if [ ! -f \"$target\" ]; then "
    "printf 'ctfos_rev_probe=%s\\n' \"$probe\"; "
    "printf '%s\\n' 'ctfos_rev_probe_status=skipped' "
    "'ctfos_rev_probe_reason=no_regular_primary_binding'; "
    "exit 0; fi; "
    "magic=$(/usr/bin/od -An -tx1 -N4 -- \"$target\" | "
    "/usr/bin/tr -d '[:space:]'); "
    "case \"$magic\" in "
    "7f454c46) ;; "
    "cafebabe) reason=java_class_non_elf ;; "
    "*) reason=unsupported_non_elf_primary ;; "
    "esac; "
    "if [ \"${reason:-}\" ]; then "
    "printf 'ctfos_rev_probe=%s\\n' \"$probe\"; "
    "printf '%s\\n' 'ctfos_rev_probe_status=skipped'; "
    "printf 'ctfos_rev_probe_reason=%s\\n' \"$reason\"; "
    "exit 0; fi; "
    "case \"$probe\" in "
    "assembly_observation) exec /usr/bin/objdump -d -- \"$target\" ;; "
    "dynamic_observation) "
    "if ! command -v ctfwrap >/dev/null 2>&1; then "
    "printf 'ctfos_rev_probe=%s\\n' \"$probe\" >&2; "
    "printf '%s\\n' 'ctfos_rev_probe_error=missing_ctfwrap' >&2; "
    "exit 2; fi; "
    "umask 077; "
    "if ! staged=$(/usr/bin/mktemp "
    "\"$work_root/ctfos-rev-dynamic.XXXXXX\"); then "
    "printf 'ctfos_rev_probe=%s\\n' \"$probe\" >&2; "
    "printf '%s\\n' 'ctfos_rev_probe_error=staging_failed' >&2; "
    "exit 2; fi; "
    "trap '/usr/bin/rm -f -- \"$staged\"' EXIT HUP INT TERM; "
    "if ! /usr/bin/cp -- \"$target\" \"$staged\"; then "
    "printf 'ctfos_rev_probe=%s\\n' \"$probe\" >&2; "
    "printf '%s\\n' 'ctfos_rev_probe_error=staging_failed' >&2; "
    "exit 2; fi; "
    "if ! /usr/bin/chmod 0500 -- \"$staged\"; then "
    "printf 'ctfos_rev_probe=%s\\n' \"$probe\" >&2; "
    "printf '%s\\n' 'ctfos_rev_probe_error=staging_failed' >&2; "
    "exit 2; fi; "
    "set +e; ctfwrap -- \"$staged\"; rc=$?; set -e; "
    "printf 'ctfos_rev_dynamic_exit=%s\\n' \"$rc\"; "
    "exit 0 ;; "
    "*) printf '%s\\n' 'ctfos_rev_probe_error=unknown_probe' >&2; "
    "exit 2 ;; "
    "esac"
)


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
                (
                    "/bin/sh",
                    "-lc",
                    _REV_ELF_PRIMARY_PROBE,
                    "ctfos-rev-elf-primary-probe",
                    "{primary}",
                    "assembly_observation",
                ),
                "function and branch locators in raw output",
                "candidate validation logic is localized",
                "format is unsupported",
                "standard",
            ),
            ExperimentSpec(
                "decompiler_observation",
                "collect an independent decompiler view",
                (
                    "/bin/sh",
                    "-lc",
                    _REV_REGULAR_PRIMARY_PROBE,
                    "ctfos-rev-regular-primary-probe",
                    "{primary}",
                    "decompiler_observation",
                ),
                "decompiled functions with locators",
                "logic agrees with execution or assembly",
                "decompiler output is missing or contradictory",
                "heavy",
                900,
            ),
            ExperimentSpec(
                "dynamic_observation",
                "observe actual executed validation path",
                (
                    "/bin/sh",
                    "-lc",
                    _REV_ELF_PRIMARY_PROBE,
                    "ctfos-rev-elf-primary-probe",
                    "{primary}",
                    "dynamic_observation",
                ),
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
