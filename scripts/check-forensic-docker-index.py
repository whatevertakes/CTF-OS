#!/usr/bin/env python3
"""Run the engine-bound Forensic index seed through a real container."""

from __future__ import annotations

import argparse
import json
import tempfile
from dataclasses import replace
from pathlib import Path

from ctf_os.config import load_config
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.images import validate_image_digest
from ctf_os.managed import ManagedOrchestrator
from ctf_os.models import (
    ChallengeIdentity,
    ChallengeStatus,
    ExperimentStatus,
)
from ctf_os.schema import STATE_SCHEMA_VERSION


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Execute the managed Forensic evidence-index seed through the "
            "digest-pinned challenge sandbox and verify its narrow reduction."
        )
    )
    parser.add_argument(
        "--image-digest",
        required=True,
        help="exact local sha256:<64 lowercase hex> Docker image ID",
    )
    return parser.parse_args()


def main() -> int:
    image_digest = validate_image_digest(
        _parse_args().image_digest
    )
    with tempfile.TemporaryDirectory(
        prefix="ctfos-forensic-docker-index-"
    ) as temporary:
        root = Path(temporary)
        config = load_config(root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                image_digest=image_digest,
            ),
        )
        engine = ChallengeEngine(root, config=config)
        identity = ChallengeIdentity(
            "release-smoke",
            "forensics",
            "evidence-index-v1",
        )
        incoming = engine.challenge_input(identity)
        incoming.mkdir(parents=True)
        (incoming / "traffic.pcapng").write_bytes(
            b"\x0a\x0d\x0d\x0a" + b"packet"
        )
        (incoming / "case.evtx").write_bytes(b"ElfFile\0event")

        initial = engine.add_challenge(
            identity,
            prompt="build a deterministic evidence index",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        legacy_ids = {
            item.id
            for item in initial.experiments
            if item.extra.get("adapter_seed") is True
        }
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=lambda digest: {
                "capabilities": {},
                "ok": digest == image_digest,
                "schema_version": 2,
            },
        )
        _reserved, session_id = orchestrator._reserve_session(
            identity,
            "S-forensic-release-smoke",
        )
        synchronized = engine.synchronize_managed_adapter_seed_plan(
            identity,
            session_id,
        )
        seed = next(
            item
            for item in synchronized.experiments
            if (
                item.id not in legacy_ids
                and item.extra.get("adapter_spec_template_id")
                == "file_inventory"
            )
        )
        _reserved, cycle = orchestrator._reserve_cycle(
            identity,
            session_id,
        )
        orchestrator._mark_action_selection(
            identity,
            session_id,
            cycle.id,
            (seed.id,),
        )
        state = engine.execute_registered_experiments(
            identity,
            experiment_ids=(seed.id,),
        )
        executed = next(
            item for item in state.experiments if item.id == seed.id
        )
        if (
            executed.status is not ExperimentStatus.COMPLETED
            or state.status is not ChallengeStatus.TRIAGING
            or executed.result is None
        ):
            raise AssertionError("Forensic index seed did not complete")
        evaluation = executed.result.get("forensic_index_execution")
        if (
            type(evaluation) is not dict
            or evaluation.get("confirmed") is not True
            or evaluation.get("reason_code")
            != "complete_executed_evidence_index"
        ):
            raise AssertionError(
                "Forensic index execution was not confirmed"
            )
        envelope = evaluation.get("envelope")
        if (
            type(envelope) is not dict
            or envelope.get("transport", {}).get("network") != "none"
        ):
            raise AssertionError("Forensic index network was not denied")
        facts = [
            item
            for item in state.facts
            if "forensic_evidence_index" in item.extra
        ]
        progress = [
            item
            for item in state.progress_markers
            if "forensic_evidence_index" in item.extra
        ]
        if (
            len(facts) != 1
            or len(progress) != 1
            or state.candidates
            or state.submissions
        ):
            raise AssertionError(
                "Forensic reduction exceeded fact/progress authority"
            )
        state.validate()
        print(
            json.dumps(
                {
                    "candidates": 0,
                    "confirmed": True,
                    "facts": len(facts),
                    "image_digest": image_digest,
                    "network": "none",
                    "ok": True,
                    "progress": len(progress),
                    "protocol": evaluation["protocol"],
                    "submissions": 0,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
