from __future__ import annotations

from .base import ExperimentSpec, GenericAdapter, ProgressMarker, ProofPolicy


class PwnAdapter(GenericAdapter):
    name = "pwn"

    def initial_observations(self) -> tuple[ExperimentSpec, ...]:
        return (
            ExperimentSpec(
                "binary_metadata",
                "identify format, architecture, and mitigations",
                ("checksec", "--file={primary}"),
                "architecture and mitigation table",
                "binary is executable and mitigations are recorded",
                "no executable challenge input exists",
            ),
            ExperimentSpec(
                "runtime_baseline",
                "observe normal and malformed-input behavior",
                (
                    "/bin/sh",
                    "-lc",
                    "set +e; umask 077; "
                    "status=/tmp/ctfos-pwn-baseline-status.$$; "
                    "trap 'rm -f \"$status\"' EXIT HUP INT TERM; "
                    "{ /usr/bin/timeout --signal=TERM --kill-after=1 3 "
                    "\"$1\" </dev/null; "
                    "printf '%s\\n' \"$?\" >\"$status\"; "
                    "} 2>&1 | /usr/bin/head -c 65536; pipe_rc=$?; "
                    "if [ -r \"$status\" ]; then "
                    "IFS= read -r rc <\"$status\" || rc=unknown; "
                    "else rc=unknown; fi; "
                    "printf '\\nctfos_runtime_baseline_exit=%s "
                    "pipe_exit=%s\\n' \"$rc\" \"$pipe_rc\"; exit 0",
                    "ctfos-pwn-runtime-baseline",
                    "{primary}",
                ),
                "bounded stdout/stderr and explicit child exit status",
                "behavior is repeatable or a crash is observed",
                "bounded runner cannot execute the binary",
                "light",
                15,
            ),
        )

    def progress_markers(self) -> tuple[ProgressMarker, ...]:
        # These are capabilities, not a strict ladder: a solve may legitimately
        # skip leak/write depending on the vulnerability.
        return tuple(
            ProgressMarker(key, label, "executed run plus exact locator")
            for key, label in (
                ("crash", "controlled crash"),
                ("control", "input controls relevant state"),
                ("leak", "useful disclosure primitive"),
                ("write", "useful write primitive"),
                ("code_execution", "controlled code execution"),
                ("flag_read", "flag source reached"),
            )
        )

    def proof_policy(self, *, remote: bool = False) -> ProofPolicy:
        return ProofPolicy(
            mode="success_distribution" if remote else "deterministic",
            clean_repetitions=3,
            remote_repetitions=0,
            trial_count=10 if remote else 0,
            minimum_success_rate=0.7 if remote else None,
            notes="race exploits report the full success/failure distribution",
        )

    def failure_labels(self) -> tuple[str, ...]:
        return (
            "no_crash",
            "offset_unstable",
            "primitive_not_exploitable",
            "remote_layout_mismatch",
            "model_refusal",
        )

    def captain_guidance(self) -> str:
        return (
            "Treat checksec and runtime behavior as independent evidence. Track "
            "capabilities as a set, not a mandatory linear ladder. Separate "
            "path validation from actually reading the intended flag."
        )
