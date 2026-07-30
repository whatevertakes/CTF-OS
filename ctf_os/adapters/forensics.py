from __future__ import annotations

from .base import ExperimentSpec, GenericAdapter, ProgressMarker, ProofPolicy


class ForensicsAdapter(GenericAdapter):
    name = "forensics"

    def initial_observations(self) -> tuple[ExperimentSpec, ...]:
        return (
            ExperimentSpec(
                "file_inventory",
                (
                    "build a bounded typed evidence index from the immutable "
                    "sandbox provenance"
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
                    "canonical JSON with source hashes, typed evidence "
                    "pointers, explicit coverage, and a graph commitment"
                ),
                (
                    "all evidence is hash-bound and the next parser can be "
                    "chosen from observed modality evidence"
                ),
                (
                    "provenance is invalid, an input changed, or pointer "
                    "coverage is insufficient"
                ),
                "light",
                300,
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
