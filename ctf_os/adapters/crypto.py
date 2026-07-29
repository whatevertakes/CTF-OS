from __future__ import annotations

from .base import ExperimentSpec, GenericAdapter, ProgressMarker, ProofPolicy


class CryptoAdapter(GenericAdapter):
    name = "crypto"

    def initial_observations(self) -> tuple[ExperimentSpec, ...]:
        return (
            ExperimentSpec(
                "source_parameters",
                "extract primitives, parameters, and sample structure",
                ("python3", "-m", "py_compile", "{primary}"),
                "syntax check plus exact parameter locators",
                "primitive and parameter scale are known",
                "input is not source code",
            ),
        )

    def progress_markers(self) -> tuple[ProgressMarker, ...]:
        return tuple(
            ProgressMarker(key, label, "parameter/source locator or executed run")
            for key, label in (
                ("paradigm_classified", "attack paradigm classified"),
                ("parameters_captured", "parameters captured"),
                ("known_attack_matched", "known attack conditions matched"),
                ("sweep_bounded", "parameter sweep bounded"),
                ("plaintext_recovered", "plaintext recovered"),
            )
        )

    def proof_policy(self, *, remote: bool = False) -> ProofPolicy:
        return ProofPolicy(
            mode="sample_matrix",
            clean_repetitions=3,
            remote_repetitions=1 if remote else 0,
            notes="preserve per-sample successes and failures separately",
        )

    def failure_labels(self) -> tuple[str, ...]:
        return (
            "wrong_paradigm",
            "parameter_scale_mismatch",
            "abstract_only_reference",
            "reimplemented_known_primitive",
            "sample_overfit",
        )

    def captain_guidance(self) -> str:
        return (
            "Classify the paradigm before writing a solver. Preserve full source "
            "documents with hashes when external knowledge is needed; abstracts "
            "alone are insufficient. Prefer vetted Sage/flatter implementations "
            "for lattice and finite-field operations."
        )

