#!/usr/bin/env python3
"""Prove the public candidate-free Rev 3+3 hot path in real Docker."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
from contextlib import ExitStack
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from ctf_os.cli import main as ctfos_main
from ctf_os.capabilities import inspect_pinned_capabilities
from ctf_os.config import (
    EngineConfig,
    RuntimeConfig,
    default_config_text,
    set_runtime_image_digest,
)
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.rev_acceptance import (
    REV_ACCEPTANCE_OPERATOR_SPEC_PROTOCOL,
    REV_ACCEPTANCE_PROTOCOL,
    canonical_json_bytes,
)
from ctf_os.engine.rev_acceptance_state import (
    validate_rev_acceptance_state_graph,
)
from ctf_os.images import validate_image_digest
from ctf_os.models import (
    ChallengeIdentity,
    ExperimentStatus,
    FactKind,
    Provenance,
    ReceiptOutcome,
    RunOrigin,
    RunStatus,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.store.atomic import atomic_write_text


REPOSITORY = Path(__file__).resolve().parent.parent
FIXTURE = (
    REPOSITORY
    / "ctf-os-image"
    / "tests"
    / "fixtures"
    / "rev-accepted-input-oracle.c"
)
RELEASE_IMAGE_DIGEST = (
    "sha256:"
    "82ef8c155a8bbe9cfe33ce1a475425c77097b6fcefc32b678da1b14bf9c8339a"
)
ACCEPTED_INPUT = b"OPEN-SESAME\n"
ACCEPTED_OUTPUT = b"REV_OK_93D1\n"
REJECTED_OUTPUT = b"REV_NO_72A4\n"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Execute the public Rev accepted-input 3+3 oracle against the "
            "repository-pinned Docker image."
        )
    )
    parser.add_argument("--image-digest", required=True)
    return parser.parse_args()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _docker(
    argv: tuple[str, ...],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ("docker", *argv),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        text=True,
        timeout=120,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"docker {' '.join(argv[:3])} failed: "
            + result.stderr.strip()[:4096]
        )
    return result


def _compile(destination: Path) -> None:
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("host cc is required")
    completed = subprocess.run(
        (
            compiler,
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(FIXTURE),
            "-o",
            str(destination),
        ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "could not compile Rev fixture: "
            + completed.stderr.decode("utf-8", errors="replace")[:4096]
        )
    destination.chmod(0o500)


def _scope_containers(qualified_id: str) -> tuple[str, ...]:
    result = _docker(
        (
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            f"label=ctfos.challenge={qualified_id}",
        )
    )
    return tuple(line for line in result.stdout.splitlines() if line)


def _cleanup_scope_containers(
    qualified_id: str,
    *,
    allowed: set[str],
) -> tuple[str, ...]:
    current = set(_scope_containers(qualified_id))
    created = sorted(current - allowed)
    for container_id in created:
        details = json.loads(
            _docker(("container", "inspect", container_id)).stdout
        )
        if (
            type(details) is not list
            or len(details) != 1
            or details[0].get("Config", {}).get("Labels", {}).get(
                "ctfos.challenge"
            )
            != qualified_id
        ):
            raise AssertionError("refused ambiguous container cleanup")
        _docker(("container", "rm", "--force", container_id))
    remaining = set(_scope_containers(qualified_id))
    if remaining != allowed:
        raise AssertionError("challenge-scoped container cleanup failed")
    return tuple(created)


def _engine(root: Path, image_digest: str) -> ChallengeEngine:
    return ChallengeEngine(
        root,
        config=EngineConfig(
            workspace_root=root,
            runtime=RuntimeConfig(
                image="ctf-os:core",
                image_digest=image_digest,
                network_default="none",
                command_timeout_s=60,
            ),
        ),
    )


def _artifact_bytes(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    artifact_id: str,
) -> bytes:
    state = engine.store.load(identity)
    artifact = next(
        item for item in state.artifacts if item.id == artifact_id
    )
    path = engine.store.challenge_paths(identity).root / artifact.path
    payload = path.read_bytes()
    if (
        _sha256(payload) != artifact.sha256
        or len(payload) != artifact.size
    ):
        raise AssertionError(f"artifact binding changed: {artifact_id}")
    return payload


def main() -> int:
    image_digest = validate_image_digest(_parse_args().image_digest)
    if image_digest != RELEASE_IMAGE_DIGEST:
        raise AssertionError(
            "release smoke requires the repository-pinned image digest"
        )
    readiness = inspect_pinned_capabilities(image_digest)
    if readiness.get("ok") is not True:
        raise AssertionError(
            "pinned image readiness failed: "
            + json.dumps(readiness, sort_keys=True)
        )
    identity = ChallengeIdentity(
        "release-smoke",
        "rev",
        "accepted-input-hotpath",
    )
    qualified_id = (
        f"{identity.contest_id}/{identity.category}/"
        f"{identity.challenge_id}"
    )
    prior_containers = set(_scope_containers(qualified_id))
    cleaned: list[str] = []

    def cleanup() -> None:
        cleaned.extend(
            _cleanup_scope_containers(
                qualified_id,
                allowed=prior_containers,
            )
        )

    with ExitStack() as cleanup_stack:
        temporary = cleanup_stack.enter_context(
            tempfile.TemporaryDirectory(
                prefix="ctfos-rev-accepted-hotpath-"
            )
        )
        cleanup_stack.callback(cleanup)
        root = Path(temporary)
        engine = _engine(root, image_digest)
        engine.config.config_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        atomic_write_text(
            engine.config.config_path,
            set_runtime_image_digest(
                default_config_text(),
                image_digest,
            ),
            mode=0o600,
        )
        incoming = engine.challenge_input(identity)
        incoming.mkdir(parents=True)
        _compile(incoming / "challenge.bin")
        state = engine.add_challenge(
            identity,
            prompt="candidate-free Rev release proof",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory_experiment = next(
            item
            for item in state.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        state = engine.execute_registered_experiments(
            identity,
            experiment_ids=(inventory_experiment.id,),
        )
        inventory_experiment = next(
            item
            for item in state.experiments
            if item.id == inventory_experiment.id
        )
        if inventory_experiment.status is not ExperimentStatus.COMPLETED:
            raise AssertionError("public Rev inventory did not confirm")
        workspace = engine._workspace(state)
        (workspace / "accepted-input.bin").write_bytes(ACCEPTED_INPUT)
        empty_sha256 = _sha256(b"")

        def expectation(
            *,
            exit_code: int,
            output: bytes,
        ) -> dict[str, object]:
            return {
                "exit_code": exit_code,
                "stderr_sha256": empty_sha256,
                "stderr_size_bytes": 0,
                "stdout_sha256": _sha256(output),
                "stdout_size_bytes": len(output),
            }

        spec = {
            "accepted": expectation(
                exit_code=0,
                output=ACCEPTED_OUTPUT,
            ),
            "accepted_input_locator": "accepted-input.bin",
            "controls": [
                {
                    "expectation": expectation(
                        exit_code=7,
                        output=REJECTED_OUTPUT,
                    ),
                    "mutation_id": mutation_id,
                }
                for mutation_id in (
                    "xor-first-01",
                    "xor-last-80",
                    "truncate-last",
                )
            ],
            "protocol": REV_ACCEPTANCE_OPERATOR_SPEC_PROTOCOL,
            "schema_version": 1,
            "source_locator": "challenge.bin",
        }
        (workspace / "rev-acceptance-spec.json").write_bytes(
            canonical_json_bytes(spec)
        )
        before_status = state.status
        cli_stdout = io.StringIO()
        cli_stderr = io.StringIO()
        with redirect_stdout(cli_stdout), redirect_stderr(cli_stderr):
            cli_exit_code = ctfos_main(
                (
                    "rev-prove-accept",
                    identity.contest_id,
                    identity.category,
                    identity.challenge_id,
                    "--spec",
                    "rev-acceptance-spec.json",
                    "--timeout",
                    "30",
                ),
                root=root,
            )
        if cli_exit_code != 0 or cli_stderr.getvalue():
            raise AssertionError(
                "public ctfos Rev gate failed: "
                + cli_stderr.getvalue()[-4096:]
                + cli_stdout.getvalue()[-4096:]
            )
        cli_summary = json.loads(cli_stdout.getvalue())
        final = engine.store.load(identity)
        validate_rev_acceptance_state_graph(final)
        experiment = next(
            item
            for item in final.experiments
            if item.result
            and isinstance(item.result, dict)
            and "rev_acceptance_evidence" in item.result
        )
        evidence = experiment.result["rev_acceptance_evidence"]
        evaluation = evidence["evaluation"]
        proof_runs = [
            item for item in final.runs if item.id in experiment.evidence_run_ids
        ]
        proof_receipts = [
            item
            for item in final.receipts
            if item.id in experiment.evidence_receipt_ids
        ]
        proof_facts = [
            item for item in final.facts if item.id in experiment.evidence_fact_ids
        ]
        proof_progress = [
            item
            for item in final.progress_markers
            if item.id == evidence["progress_id"]
        ]
        if (
            evaluation["protocol"] != REV_ACCEPTANCE_PROTOCOL
            or evaluation["passed"] is not True
            or evaluation["reason_codes"]
            or len(evaluation["observations"]) != 6
            or len(proof_runs) != 6
            or len(proof_receipts) != 6
            or any(
                item.status is not RunStatus.COMPLETED
                or item.origin is not RunOrigin.OPERATOR_TOOL
                for item in proof_runs
            )
            or any(
                item.outcome is not ReceiptOutcome.SUCCEEDED
                for item in proof_receipts
            )
            or len(proof_facts) != 1
            or proof_facts[0].kind is not FactKind.OBSERVATION
            or proof_facts[0].provenance is not Provenance.EXECUTED
            or len(proof_progress) != 1
            or final.candidates
            or final.submissions
            or final.status is not before_status
            or cli_summary["passed"] is not True
            or cli_summary["run_count"] != 6
            or cli_summary["state_revision"] != final.revision
        ):
            raise AssertionError(
                "public Rev accepted-input state authority is incomplete"
            )
        for record in evidence["records"]:
            observation = record["observation"]
            _artifact_bytes(
                engine,
                identity,
                observation["stdout_artifact_id"],
            )
            _artifact_bytes(
                engine,
                identity,
                observation["stderr_artifact_id"],
            )
            for prefix in ("request", "result", "validation"):
                payload = (
                    engine.store.challenge_paths(identity).root
                    / record[f"{prefix}_path"]
                ).read_bytes()
                if (
                    _sha256(payload) != record[f"{prefix}_sha256"]
                    or len(payload) != record[f"{prefix}_size_bytes"]
                ):
                    raise AssertionError(
                        f"{prefix} record pointer/hash changed"
                    )
        state_payload = engine.store.challenge_paths(
            identity
        ).state.read_bytes()
        if (
            ACCEPTED_INPUT.rstrip() in state_payload
            or ACCEPTED_OUTPUT.rstrip() in state_payload
            or REJECTED_OUTPUT.rstrip() in state_payload
        ):
            raise AssertionError("raw Rev secret/output entered state.json")
    print(
        json.dumps(
            {
                "candidates": 0,
                "cleaned_containers": len(cleaned),
                "fact_count": 1,
                "image_digest": image_digest,
                "network": "none",
                "ok": True,
                "progress_count": 1,
                "protocol": REV_ACCEPTANCE_PROTOCOL,
                "receipts": 6,
                "runs": 6,
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
