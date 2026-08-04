from __future__ import annotations

from .base import ExperimentSpec, GenericAdapter, ProgressMarker, ProofPolicy


_PRIMARY_MAGIC = (
    "set -eu; target=$1; "
    "if [ -L \"$target\" ]; then "
    "printf '%s\\n' 'ctfos_primary_magic_error=symlink_source_binding' "
    ">&2; exit 2; fi; "
    "if [ ! -f \"$target\" ]; then "
    "printf '%s\\n' 'ctfos_primary_magic_mode=skipped' "
    "'ctfos_primary_magic_reason=no_regular_source_binding'; "
    "exit 0; fi; "
    "exec /usr/bin/file --brief --mime-type -- \"$target\""
)

_PRIMARY_STRINGS = (
    "set -eu; target=$1; "
    "if [ -L \"$target\" ]; then "
    "printf '%s\\n' 'ctfos_primary_strings_error=symlink_source_binding' "
    ">&2; exit 2; fi; "
    "if [ ! -f \"$target\" ]; then "
    "printf '%s\\n' 'ctfos_primary_strings_mode=skipped' "
    "'ctfos_primary_strings_reason=no_regular_source_binding'; "
    "exit 0; fi; "
    "/usr/bin/strings -a -n 6 -- \"$target\" "
    "| /usr/bin/head -c 65536"
)


class MiscAdapter(GenericAdapter):
    """Evidence-diverse intake for challenges whose modality is not known yet."""

    name = "misc"

    def initial_observations(self) -> tuple[ExperimentSpec, ...]:
        # These probes intentionally use three different evidence generators.
        # Provider concurrency may queue their evaluation, but the logical
        # frontier remains three-wide.
        return (
            ExperimentSpec(
                "typed_inventory",
                (
                    "build a bounded immutable inventory and classify every "
                    "input by magic and extension"
                ),
                (
                    "/usr/bin/python3",
                    "/opt/ctf-templates/forensic/evidence_index.py",
                    "--root",
                    "/challenge",
                    "--tree",
                    "/work/.ctf/challenge.tree",
                    "--metadata",
                    "/work/.ctf/challenge.json",
                ),
                (
                    "hash-bound file records plus modality and format counts"
                ),
                (
                    "the modality frontier is updated from exact indexed "
                    "artifacts"
                ),
                (
                    "the immutable source provenance is invalid or no input "
                    "can be indexed"
                ),
                "light",
                300,
            ),
            ExperimentSpec(
                "primary_magic",
                "identify the primary artifact independently by libmagic",
                (
                    "/bin/sh",
                    "-lc",
                    _PRIMARY_MAGIC,
                    "ctfos-misc-primary-magic",
                    "{primary}",
                ),
                "one bounded MIME classification for the primary artifact",
                (
                    "the MIME observation changes at least one modality "
                    "probability"
                ),
                "libmagic cannot classify the immutable primary artifact",
                "light",
                30,
            ),
            ExperimentSpec(
                "primary_strings",
                (
                    "sample bounded printable structure for protocol, jail, "
                    "PPC, and embedded-format clues"
                ),
                (
                    "/bin/sh",
                    "-lc",
                    _PRIMARY_STRINGS,
                    "ctfos-misc-primary-strings",
                    "{primary}",
                ),
                "at most 65536 bytes of printable primary-artifact structure",
                (
                    "prompts, grammar, encodings, or embedded signatures "
                    "discriminate between modalities"
                ),
                "the bounded sample contains no discriminating structure",
                "light",
                30,
            ),
        )

    def progress_markers(self) -> tuple[ProgressMarker, ...]:
        return (
            ProgressMarker(
                "modality_frontier",
                "modality posterior recorded",
                (
                    "three probability-bearing hypotheses tied to independent "
                    "executed observations"
                ),
            ),
            ProgressMarker(
                "transform_graph",
                "transformation DAG recorded",
                "input/output hashes and exact parent bindings for every step",
            ),
            ProgressMarker(
                "candidate_produced",
                "candidate artifact produced",
                "terminal DAG artifact and replayable sandbox receipt",
            ),
            ProgressMarker(
                "original_oracle",
                "original condition verified",
                "three clean independent verifier receipts",
            ),
        )

    def proof_policy(self, *, remote: bool = False) -> ProofPolicy:
        return ProofPolicy(
            mode="transform_dag_reverse_oracle",
            clean_repetitions=3,
            remote_repetitions=1 if remote else 0,
            notes=(
                "the terminal artifact must be reverse-checked against the "
                "immutable original input by a different pinned tool"
            ),
        )

    def failure_labels(self) -> tuple[str, ...]:
        return (
            "modality_premature_lock",
            "transform_hash_mismatch",
            "wrong_tool",
            "unsupported_format",
            "oracle_rejected",
            "non_reproducible",
        )

    def captain_guidance(self) -> str:
        return (
            "Start with this modality prior: stego=0.35, "
            "custom_protocol=0.25, audio_signal=0.15, jail=0.10, "
            "ppc=0.10, other=0.05. Preserve at least three independent "
            "hypothesis contracts even when provider calls queue. Update the "
            "posterior only from executed typed-inventory, libmagic, or "
            "bounded-strings evidence, and do not lock a modality until two "
            "independent observations support it or a deterministic oracle "
            "rules alternatives out. Store every transform as a DAG node with "
            "exact input/output hashes, prefer cheap rollback, and accept a "
            "terminal candidate only after three clean reverse-oracle runs "
            "against the immutable original input."
        )
