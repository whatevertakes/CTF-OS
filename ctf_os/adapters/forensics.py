from __future__ import annotations

from .base import ExperimentSpec, GenericAdapter, ProgressMarker, ProofPolicy


class ForensicsAdapter(GenericAdapter):
    name = "forensics"

    def initial_observations(self) -> tuple[ExperimentSpec, ...]:
        return (
            ExperimentSpec(
                "file_inventory",
                "detect types and hashes without modifying evidence",
                ("find", "/challenge", "-type", "f", "-maxdepth", "3"),
                "file inventory linked to source hashes",
                "evidence types and next parser are known",
                "evidence is missing or unreadable",
            ),
        )

    def progress_markers(self) -> tuple[ProgressMarker, ...]:
        return tuple(
            ProgressMarker(key, label, "source hash, extraction path, artifact hash")
            for key, label in (
                ("types_detected", "evidence types detected"),
                ("dependencies_mapped", "question dependencies mapped"),
                ("timeline_built", "relevant timeline built"),
                ("artifact_extracted", "target artifact extracted"),
                ("artifact_verified", "extraction verified"),
            )
        )

    def proof_policy(self, *, remote: bool = False) -> ProofPolicy:
        return ProofPolicy(
            mode="hash_chain",
            clean_repetitions=1,
            notes="verify source hash -> extraction path -> result hash",
        )

    def failure_labels(self) -> tuple[str, ...]:
        return (
            "wrong_profile",
            "dependency_blocked",
            "wrong_command",
            "truncated_evidence",
            "unproven_extraction",
        )

    def captain_guidance(self) -> str:
        return (
            "Separate detection from dissection. Maintain a dependency graph and "
            "do not spend budget on downstream questions while a prerequisite is "
            "blocked. Keep raw output external and preserve the evidence hash chain."
        )

