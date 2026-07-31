#!/usr/bin/env python3
"""Execute the three-way Misc modality intake in the production sandbox."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from ctf_os.adapters import get_adapter
from ctf_os.capabilities import inspect_pinned_capabilities
from ctf_os.config import load_config
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.context_pack import build_context_pack
from ctf_os.images import validate_image_digest
from ctf_os.managed import ManagedOrchestrator
from ctf_os.models import (
    ChallengeIdentity,
    ChallengeStatus,
    ExperimentStatus,
    ReceiptOutcome,
    RunOrigin,
    SessionStatus,
)
from ctf_os.sandbox.files import read_bounded_regular
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.store.atomic import read_json, strict_json_loads


PROBE_IDS = ("typed_inventory", "primary_magic", "primary_strings")
PRINTABLE_MARKER = b"CTFOS-MISC-PROTOCOL-MARKER SEND LENGTH PAYLOAD"

# One small valid PNG followed by a printable protocol clue.  The appended
# bytes are permitted by the PNG format and let libmagic and strings generate
# independent observations from the exact same immutable primary artifact.
PNG_FIXTURE = bytes.fromhex(
    "89504e470d0a1a0a"
    "0000000d49484452000000010000000108060000001f15c489"
    "0000000d4944415408d763f8cfc0f01f00050001ff89993d1d"
    "0000000049454e44ae426082"
) + b"\n" + PRINTABLE_MARKER + b"\n"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Require all three Misc modality probes to execute through the "
            "exact deny-all release image."
        )
    )
    parser.add_argument("--image-digest", required=True)
    return parser.parse_args()


def _docker_containers(identity: ChallengeIdentity) -> tuple[str, ...]:
    result = subprocess.run(
        (
            "docker",
            "ps",
            "-aq",
            "--filter",
            "label=ctfos.managed=true",
            "--filter",
            (
                "label=ctfos.challenge="
                f"{identity.contest_id}/{identity.category}/"
                f"{identity.challenge_id}"
            ),
        ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError("could not inspect release containers")
    values = tuple(
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    )
    if any(
        len(value) < 12
        or any(character not in "0123456789abcdef" for character in value)
        for value in values
    ):
        raise RuntimeError("Docker returned an invalid container identifier")
    return values


def _artifact_payload(engine: ChallengeEngine, state, artifact_id: str) -> bytes:
    matches = [item for item in state.artifacts if item.id == artifact_id]
    if len(matches) != 1:
        raise AssertionError("stdout artifact identity is not unique")
    artifact = matches[0]
    if artifact.size is None:
        raise AssertionError("stdout artifact size is missing")
    payload = read_bounded_regular(
        engine.store.challenge_paths(state.identity).root,
        artifact.path,
        maximum_bytes=4 * 1024 * 1024,
        expected_sha256=artifact.sha256,
        expected_size=artifact.size,
    )
    return payload


def main() -> int:
    image_digest = validate_image_digest(_parse_args().image_digest)

    with tempfile.TemporaryDirectory(
        prefix="ctfos-misc-modality-release-"
    ) as temporary:
        root = Path(temporary)
        configured = load_config(root)
        configured = replace(
            configured,
            runtime=replace(
                configured.runtime,
                image="ctf-os:core",
                image_digest=image_digest,
                network_default="none",
                command_timeout_s=300,
            ),
            resources=replace(
                configured.resources,
                remote_command_min_interval_s=0.0,
            ),
        )
        engine = ChallengeEngine(
            root,
            config=configured,
            capability_probe=inspect_pinned_capabilities,
        )
        engine._sandbox_factory = None
        identity = ChallengeIdentity(
            "release-smoke",
            "misc",
            "modality-frontier-v1",
        )
        incoming = engine.challenge_input(identity)
        incoming.mkdir(parents=True)
        (incoming / "challenge.png").write_bytes(PNG_FIXTURE)
        (incoming / "notes.txt").write_text(
            "independent inventory companion\n",
            encoding="ascii",
        )

        initial = engine.add_challenge(
            identity,
            prompt="classify without locking one Misc modality",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        legacy_ids = {
            item.id
            for item in initial.experiments
            if item.extra.get("adapter_seed") is True
        }
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=inspect_pinned_capabilities,
        )
        _reserved, session_id = orchestrator._reserve_session(
            identity,
            "S-misc-modality-release",
        )
        synchronized = engine.synchronize_managed_adapter_seed_plan(
            identity,
            session_id,
        )
        selected = tuple(
            item
            for item in synchronized.experiments
            if (
                item.id not in legacy_ids
                and item.status is ExperimentStatus.REGISTERED
                and item.extra.get("adapter_seed") is True
            )
        )
        if (
            len(selected) != len(PROBE_IDS)
            or tuple(
                item.extra.get("adapter_spec_template_id")
                for item in selected
            )
            != PROBE_IDS
        ):
            raise AssertionError("Misc modality frontier was narrowed")

        _reserved, cycle = orchestrator._reserve_cycle(
            identity,
            session_id,
        )
        selected_ids = tuple(item.id for item in selected)
        orchestrator._mark_action_selection(
            identity,
            session_id,
            cycle.id,
            selected_ids,
        )
        state = orchestrator._execute_selected_actions(
            identity,
            selected_ids,
        )

        executed = {
            item.extra.get("adapter_spec_template_id"): item
            for item in state.experiments
            if item.id in selected_ids
        }
        if (
            set(executed) != set(PROBE_IDS)
            or any(
                item.status is not ExperimentStatus.COMPLETED
                for item in executed.values()
            )
        ):
            raise AssertionError("a Misc modality probe did not complete")

        receipts = {
            receipt.experiment_id: receipt
            for receipt in state.receipts
            if receipt.experiment_id in selected_ids
        }
        if (
            len(receipts) != len(PROBE_IDS)
            or any(
                receipt.outcome is not ReceiptOutcome.SUCCEEDED
                or receipt.stdout_artifact_id is None
                for receipt in receipts.values()
            )
        ):
            raise AssertionError("Misc modality receipts are incomplete")

        outputs: dict[str, bytes] = {}
        for probe_id, experiment in executed.items():
            receipt = receipts[experiment.id]
            assert receipt.stdout_artifact_id is not None
            outputs[probe_id] = _artifact_payload(
                engine,
                state,
                receipt.stdout_artifact_id,
            )

        inventory = strict_json_loads(outputs["typed_inventory"])
        if (
            inventory.get("contract", {}).get("id")
            != "ctfos.forensic.evidence_index"
            or inventory.get("coverage", {}).get("hash_bound_files") != 2
            or inventory.get("type_summary", {})
            .get("modalities", {})
            .get("image")
            != 1
            or inventory.get("source", {}).get("mount_read_only") is not True
        ):
            raise AssertionError("typed Misc inventory is not hash-bound")
        if outputs["primary_magic"].strip() != b"image/png":
            raise AssertionError("libmagic did not independently identify PNG")
        if (
            PRINTABLE_MARKER not in outputs["primary_strings"]
            or len(outputs["primary_strings"]) > 65536
        ):
            raise AssertionError("bounded strings probe did not discriminate")

        run_by_id = {
            item.id: item
            for item in state.runs
            if item.origin is RunOrigin.MANAGED_TOOL
            and item.id in {receipt.run_id for receipt in receipts.values()}
        }
        if len(run_by_id) != len(PROBE_IDS):
            raise AssertionError("Misc probes were not managed tool runs")
        paths = engine.store.challenge_paths(identity)
        for run in run_by_id.values():
            if run.request_path is None:
                raise AssertionError("Misc probe request pointer is missing")
            request = read_json(paths.root / run.request_path)
            if (
                request.get("image_digest") != image_digest
                or request.get("network_target") is not None
                or request.get("resource_request", {}).get("network") != 0
                or request.get("requires_explicit_execution") is not True
            ):
                raise AssertionError("Misc probe escaped its deny-all binding")

        context = build_context_pack(
            state,
            get_adapter("misc"),
            state_path=paths.state,
            max_chars=64 * 1024,
        )
        if (
            "stego=0.35" not in context.text
            or "custom_protocol=0.25" not in context.text
            or "three independent" not in context.text
        ):
            raise AssertionError("Misc posterior contract missed model context")
        if (
            state.status is not ChallengeStatus.TRIAGING
            or state.candidates
            or state.submissions
        ):
            raise AssertionError("Misc intake exceeded observation authority")

        state = orchestrator._finish_session(
            identity,
            session_id,
            status=SessionStatus.COMPLETED,
            reason="three-way Misc modality intake confirmed",
        )
        state.validate()
        if _docker_containers(identity):
            raise AssertionError("Misc release containers were not removed")

        print(
            json.dumps(
                {
                    "candidates": 0,
                    "image_digest": image_digest,
                    "network": "none",
                    "ok": True,
                    "probe_ids": list(PROBE_IDS),
                    "probe_runs": len(run_by_id),
                    "source_sha256": hashlib.sha256(PNG_FIXTURE).hexdigest(),
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
