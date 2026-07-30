#!/usr/bin/env python3
"""Exercise managed ``rev_accepted_input`` through real pinned Docker."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import threading
from contextlib import ExitStack
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from ctf_os.capabilities import inspect_pinned_capabilities
from ctf_os.codex import (
    BatchRunner,
    FifoModelCallLimiter,
    ProcessOutcome,
    Role,
)
from ctf_os.config import EngineConfig, RuntimeConfig
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.rev_acceptance import (
    REV_ACCEPTANCE_OPERATOR_SPEC_PROTOCOL,
    REV_ACCEPTANCE_PROTOCOL,
    RevAcceptanceOperatorSpec,
    canonical_json_bytes,
)
from ctf_os.engine.rev_acceptance_state import (
    validate_rev_acceptance_state_graph,
)
from ctf_os.images import validate_image_digest
from ctf_os.managed import ManagedOrchestrator
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


FIXTURE = (
    REPOSITORY
    / "ctf-os-image"
    / "tests"
    / "fixtures"
    / "rev-accepted-input-oracle.c"
)
RELEASE_IMAGE_DIGEST = (
    "sha256:"
    "f39d2216ddaa93fae3134014b25be0609096bacd8648b1621121787db6196338"
)
ACCEPTED_INPUT = b"OPEN-SESAME\n"
ACCEPTED_OUTPUT = b"REV_OK_93D1\n"
REJECTED_OUTPUT = b"REV_NO_72A4\n"


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image-digest", required=True)
    return parser.parse_args()


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
            "could not compile managed Rev fixture: "
            + completed.stderr.decode(
                "utf-8",
                errors="replace",
            )[:4096]
        )
    destination.chmod(0o500)


def _scope_containers(qualified_id: str) -> set[str]:
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
    return set(result.stdout.splitlines())


def _cleanup_scope_containers(
    qualified_id: str,
    *,
    allowed: set[str],
) -> int:
    created = sorted(_scope_containers(qualified_id) - allowed)
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
    if _scope_containers(qualified_id) != allowed:
        raise AssertionError("managed Rev container cleanup failed")
    return len(created)


def _expectation(
    *,
    exit_code: int,
    output: bytes,
) -> dict[str, object]:
    return {
        "exit_code": exit_code,
        "stderr_sha256": _sha256(b""),
        "stderr_size_bytes": 0,
        "stdout_sha256": _sha256(output),
        "stdout_size_bytes": len(output),
    }


def _operator_spec() -> dict[str, object]:
    return {
        "accepted": _expectation(
            exit_code=0,
            output=ACCEPTED_OUTPUT,
        ),
        "accepted_input_locator": "rev/accepted-input.bin",
        "controls": [
            {
                "expectation": _expectation(
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


def _none_action() -> dict[str, object]:
    return {
        "kind": "none",
        "description": "no model-owned execution",
        "command": None,
        "artifact_path": None,
        "hypothesis_ids": [],
        "expected_observation": "",
        "keep_if": "",
        "drop_if": "",
        "timeout_seconds": 1,
        "resource_class": "light",
        "network_target_id": None,
        "network_target_generation": None,
    }


def _base_payload(role: Role) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": 2,
        "role": role.value,
        "status": "ok",
        "summary": "bounded managed Rev release observation",
        "observations": [],
        "hypotheses": [],
        "hypothesis_updates": [],
        "evaluations": [],
        "actions": [_none_action()],
        "artifacts": [],
        "progress_markers": [],
        "flag_candidates": [],
        "decision": None,
        "goal_update": None,
        "refusal": None,
    }
    if role is Role.CAPTAIN:
        payload["observations"] = [
            {
                "id": "obs-1",
                "claim": "the original-binary Rev gate is ready",
                "evidence": ["current deterministic inventory"],
                "provenance": "executed",
            }
        ]
        payload["hypotheses"] = [
            {
                "id": f"rev-hyp-{index}",
                "claim": f"accepted-input hypothesis {index}",
                "evidence": ["obs-1"],
                "unknowns": ["original binary acceptance"],
                "experiment": "run the fixed 3+3 gate",
                "success_oracle": "all exact observations match",
                "falsifier": "any exact observation differs",
            }
            for index in range(1, 4)
        ]
        payload["decision"] = {
            "next_stage": "attack",
            "reason": "execute the managed Rev accepted-input gate",
        }
    return payload


def _role_and_output_path(command) -> tuple[Role, Path]:
    schema_index = command.argv.index("--output-schema")
    schema = json.loads(
        Path(command.argv[schema_index + 1]).read_text(
            encoding="utf-8"
        )
    )
    title = str(schema["title"])
    role = Role(
        title.removeprefix("CTF-OS ").removesuffix(" result")
    )
    output_index = command.argv.index("--output-last-message")
    return role, Path(command.argv[output_index + 1])


class _ManagedRevRoleExecutor:
    """Deterministic model-output fixture; only Docker executes the oracle."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._calls = 0
        self.spec_payload = canonical_json_bytes(_operator_spec())
        self.spec = RevAcceptanceOperatorSpec.from_mapping(
            _operator_spec()
        )

    def run(
        self,
        command,
        *,
        cwd,
        timeout,
        on_stdout_line,
    ) -> ProcessOutcome:
        del timeout
        role, output_path = _role_and_output_path(command)
        with self._lock:
            self._calls += 1
            call = self._calls
        on_stdout_line(
            json.dumps(
                {
                    "type": "thread.started",
                    "thread_id": f"managed-rev-{role.value}-{call}",
                }
            )
            + "\n"
        )
        payload = _base_payload(role)
        if role is Role.BUILDER:
            working = Path(cwd)
            spec_path = working / "rev" / "operator-spec.json"
            input_path = working / "rev" / "accepted-input.bin"
            spec_path.parent.mkdir(parents=True, exist_ok=True)
            spec_path.write_bytes(self.spec_payload)
            input_path.write_bytes(ACCEPTED_INPUT)
            payload["artifacts"] = [
                {
                    "path": "rev/operator-spec.json",
                    "sha256": _sha256(self.spec_payload),
                    "purpose": "hash-only Rev operator specification",
                },
                {
                    "path": "rev/accepted-input.bin",
                    "sha256": _sha256(ACCEPTED_INPUT),
                    "purpose": "engine-private accepted input",
                },
            ]
            payload["actions"] = [
                {
                    "kind": "rev_accepted_input",
                    "operator_spec_artifact_path": (
                        "rev/operator-spec.json"
                    ),
                    "operator_spec_sha256": _sha256(
                        self.spec_payload
                    ),
                    "accepted_input_artifact_path": (
                        "rev/accepted-input.bin"
                    ),
                    "accepted_input_sha256": _sha256(ACCEPTED_INPUT),
                    "declared_argv": [
                        "/usr/bin/python3",
                        "/opt/ctf-templates/rev/stdin_exec.py",
                        "--binary",
                        "/challenge/challenge.bin",
                        "--input",
                        "/work/oracle/accepted-input.bin",
                    ],
                    "expected_oracle": self.spec.expected_oracle,
                }
            ]
        output_path.write_text(
            json.dumps(payload),
            encoding="utf-8",
        )
        return ProcessOutcome(0, "", 0.01)


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
        "managed-accepted-input-hotpath",
    )
    qualified_id = (
        f"{identity.contest_id}/{identity.category}/"
        f"{identity.challenge_id}"
    )
    prior_containers = _scope_containers(qualified_id)
    cleaned = 0
    with ExitStack() as stack:
        temporary = stack.enter_context(
            tempfile.TemporaryDirectory(
                prefix="ctfos-managed-rev-accepted-"
            )
        )

        def cleanup() -> None:
            nonlocal cleaned
            cleaned = _cleanup_scope_containers(
                qualified_id,
                allowed=prior_containers,
            )

        stack.callback(cleanup)
        root = Path(temporary)
        executor = _ManagedRevRoleExecutor()
        engine = ChallengeEngine(
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
            batch_runner=BatchRunner(
                process_executor=executor,
                limiter=FifoModelCallLimiter(1),
                max_schema_retries=0,
            ),
        )
        incoming = engine.challenge_input(identity)
        incoming.mkdir(parents=True)
        _compile(incoming / "challenge.bin")
        initial = engine.add_challenge(
            identity,
            prompt="managed candidate-free Rev release proof",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        state = ManagedOrchestrator(engine).run_cycle(identity)
        validate_rev_acceptance_state_graph(state)
        managed = [
            item
            for item in state.experiments
            if item.extra.get("managed_action_kind")
            == "rev_accepted_input"
        ]
        proofs = [
            item
            for item in state.experiments
            if isinstance(item.result, dict)
            and "rev_acceptance_evidence" in item.result
        ]
        if len(managed) != 1 or len(proofs) != 1:
            raise AssertionError("managed Rev action did not dispatch once")
        wrapper = managed[0]
        proof = proofs[0]
        evidence = proof.result["rev_acceptance_evidence"]
        evaluation = evidence["evaluation"]
        proof_runs = [
            item
            for item in state.runs
            if item.id in proof.evidence_run_ids
        ]
        proof_receipts = [
            item
            for item in state.receipts
            if item.id in proof.evidence_receipt_ids
        ]
        proof_facts = [
            item
            for item in state.facts
            if item.id in proof.evidence_fact_ids
        ]
        proof_progress = [
            item
            for item in state.progress_markers
            if item.id == evidence["progress_id"]
        ]
        request = wrapper.extra["managed_typed_gate_request"]
        checks = {
            "wrapper_completed": (
                wrapper.status is ExperimentStatus.COMPLETED
            ),
            "wrapper_passed": wrapper.result.get("passed") is True,
            "protocol": (
                evaluation["protocol"] == REV_ACCEPTANCE_PROTOCOL
            ),
            "evaluation_passed": evaluation["passed"] is True,
            "reason_codes_empty": not evaluation["reason_codes"],
            "observations_six": len(evaluation["observations"]) == 6,
            "runs_six": len(proof_runs) == 6,
            "runs_canonical": not any(
                item.status is not RunStatus.COMPLETED
                or item.origin is not RunOrigin.MANAGED_TOOL
                for item in proof_runs
            ),
            "receipts_six": len(proof_receipts) == 6,
            "receipts_succeeded": not any(
                item.outcome is not ReceiptOutcome.SUCCEEDED
                for item in proof_receipts
            ),
            "fact_exact": (
                len(proof_facts) == 1
                and proof_facts[0].kind is FactKind.OBSERVATION
                and proof_facts[0].provenance is Provenance.EXECUTED
            ),
            "progress_exact": len(proof_progress) == 1,
            "candidate_free": not state.candidates,
            "submission_free": not state.submissions,
            "authorities_zero": evaluation["authorities"]
            == {
                "automatic_submission_authorized": False,
                "candidate_authorized": False,
                "challenge_status_transition_authorized": False,
                "flag_proven": False,
            },
            "request_value_free": not any(
                field in request
                for field in (
                    "candidate",
                    "candidate_id",
                    "verdict",
                    "flag",
                    "accepted_input",
                )
            ),
        }
        failed_checks = sorted(
            name for name, passed in checks.items() if not passed
        )
        if failed_checks:
            raise AssertionError(
                "managed Rev accepted-input authority is incomplete: "
                + ",".join(failed_checks)
            )
        request_payload = canonical_json_bytes(request)
        if (
            ACCEPTED_INPUT.rstrip() in request_payload
            or ACCEPTED_OUTPUT.rstrip() in request_payload
            or REJECTED_OUTPUT.rstrip() in request_payload
        ):
            raise AssertionError(
                "raw Rev input/output entered the managed action request"
            )
    print(
        json.dumps(
            {
                "candidates": 0,
                "cleaned_containers": cleaned,
                "fact_count": 1,
                "image_digest": image_digest,
                "managed_action": "rev_accepted_input",
                "network": "none",
                "ok": True,
                "progress_count": 1,
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
