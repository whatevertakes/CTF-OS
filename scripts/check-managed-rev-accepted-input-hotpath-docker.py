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
    REV_ACCEPTANCE_MAX_EVIDENCE_BYTES,
    REV_ACCEPTANCE_MAX_INPUT_BYTES,
    REV_ACCEPTANCE_MAX_SPEC_BYTES,
    REV_ACCEPTANCE_MAX_STREAM_BYTES,
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
from ctf_os.sandbox.files import read_bounded_regular
from ctf_os.schema import STATE_SCHEMA_VERSION


FIXTURE = (
    REPOSITORY
    / "ctf-os-image"
    / "tests"
    / "fixtures"
    / "rev-accepted-input-oracle.c"
)
ACCEPTED_INPUT = b"OPEN-SESAME\n"
ACCEPTED_OUTPUT = b"REV_OK_93D1\n"
REJECTED_OUTPUT = b"REV_NO_72A4\n"
ORACLE_ARGV = [
    "/usr/bin/python3",
    "/opt/ctf-templates/rev/stdin_exec.py",
    "--binary",
    "/challenge/challenge.bin",
    "--input",
    "/work/oracle/accepted-input.bin",
]
_REQUEST_KEYS = frozenset(
    {
        "argv",
        "base_revision",
        "category",
        "challenge_id",
        "configuration_epoch",
        "contest_id",
        "created_at",
        "experiment_id",
        "image_digest",
        "input_sha256",
        "input_size_bytes",
        "kind",
        "mutation_id",
        "network",
        "ordinal",
        "phase",
        "protocol",
        "resource_request",
        "run_id",
        "schema_version",
        "source_manifest_sha256",
        "source_sha256",
    }
)
_RESULT_KEYS = frozenset(
    {
        "artifacts",
        "category",
        "challenge_id",
        "contest_id",
        "rev_acceptance_observation",
        "run_id",
        "schema_version",
        "status",
    }
)
_VALIDATION_KEYS = frozenset(
    {
        "rev_acceptance_observation",
        "run_id",
        "status",
        "validated_at",
    }
)
_RESOURCE_REQUEST = {
    "cpu": 2,
    "gpu": 0,
    "kvm": 0,
    "memory_mib": 4096,
    "network": 0,
}


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
            "selected_experiment": None,
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
                    "declared_argv": list(ORACLE_ARGV),
                    "expected_oracle": self.spec.expected_oracle,
                }
            ]
        output_path.write_text(
            json.dumps(payload),
            encoding="utf-8",
        )
        return ProcessOutcome(0, "", 0.01)


def _read_bound_json(
    challenge_root: Path,
    record: dict[str, object],
    prefix: str,
    *,
    ordinal: int,
) -> dict[str, object]:
    try:
        locator = record[f"{prefix}_path"]
        expected_sha256 = record[f"{prefix}_sha256"]
        expected_size = record[f"{prefix}_size_bytes"]
        if (
            type(locator) is not str
            or type(expected_sha256) is not str
            or type(expected_size) is not int
        ):
            raise ValueError("record binding is not typed")
        payload = read_bounded_regular(
            challenge_root,
            locator,
            maximum_bytes=REV_ACCEPTANCE_MAX_EVIDENCE_BYTES,
            expected_sha256=expected_sha256,
            expected_size=expected_size,
        )
        document = json.loads(payload)
    except (KeyError, OSError, UnicodeError, ValueError) as error:
        raise AssertionError(
            f"Rev physical record {ordinal} {prefix} changed"
        ) from error
    if type(document) is not dict:
        raise AssertionError(
            f"Rev physical record {ordinal} {prefix} is not an object"
        )
    return document


def _read_bound_artifact(
    challenge_root: Path,
    artifact,
    *,
    maximum_bytes: int,
    label: str,
) -> bytes:
    try:
        return read_bounded_regular(
            challenge_root,
            artifact.path,
            maximum_bytes=maximum_bytes,
            expected_sha256=artifact.sha256,
            expected_size=artifact.size,
        )
    except (OSError, ValueError) as error:
        raise AssertionError(
            f"Rev physical {label} artifact changed"
        ) from error


def _validated_physical_rev_execution(
    state,
    proof,
    *,
    challenge_root: Path,
    image_digest: str,
) -> tuple[list[object], list[object]]:
    """Reconstruct all six Rev attempts from committed physical bytes."""

    evidence = proof.result.get("rev_acceptance_evidence")
    if type(evidence) is not dict:
        raise AssertionError("Rev physical evidence binding is absent")
    records = evidence.get("records")
    evaluation = evidence.get("evaluation")
    plan = evidence.get("plan")
    if (
        type(records) is not list
        or len(records) != 6
        or type(evaluation) is not dict
        or evaluation.get("passed") is not True
        or evaluation.get("reason_codes") != []
        or type(plan) is not list
        or len(plan) != 6
        or evidence.get("image_digest") != image_digest
        or evidence.get("protocol") != REV_ACCEPTANCE_PROTOCOL
    ):
        raise AssertionError("Rev physical evaluation is incomplete")
    artifacts = {item.id: item for item in state.artifacts}
    runs = {item.id: item for item in state.runs}
    receipts = {item.id: item for item in state.receipts}
    if (
        len(artifacts) != len(state.artifacts)
        or len(runs) != len(state.runs)
        or len(receipts) != len(state.receipts)
    ):
        raise AssertionError("Rev state identities are not unique")

    for binding_name, maximum in (
        ("operator_spec_artifact", REV_ACCEPTANCE_MAX_SPEC_BYTES),
        ("accepted_input_artifact", REV_ACCEPTANCE_MAX_INPUT_BYTES),
    ):
        binding = evidence.get(binding_name)
        artifact = (
            artifacts.get(binding.get("artifact_id"))
            if type(binding) is dict
            else None
        )
        if (
            artifact is None
            or artifact.path != binding.get("path")
            or artifact.sha256 != binding.get("sha256")
            or artifact.size != binding.get("size_bytes")
        ):
            raise AssertionError(
                f"Rev physical {binding_name} is not state-bound"
            )
        _read_bound_artifact(
            challenge_root,
            artifact,
            maximum_bytes=maximum,
            label=binding_name,
        )

    evaluation_artifact = artifacts.get(
        evidence.get("evaluation_artifact_id")
    )
    evaluation_payload = canonical_json_bytes(evaluation)
    if (
        evaluation_artifact is None
        or evaluation_artifact.sha256
        != evidence.get("evaluation_sha256")
        or evaluation_artifact.size != len(evaluation_payload)
        or _read_bound_artifact(
            challenge_root,
            evaluation_artifact,
            maximum_bytes=REV_ACCEPTANCE_MAX_EVIDENCE_BYTES,
            label="evaluation",
        )
        != evaluation_payload
    ):
        raise AssertionError("Rev physical evaluation is not exact")

    ordered_runs: list[object] = []
    ordered_receipts: list[object] = []
    observations = evaluation.get("observations")
    if type(observations) is not list or len(observations) != 6:
        raise AssertionError("Rev physical observations are incomplete")
    for ordinal, (record, observation, plan_item) in enumerate(
        zip(records, observations, plan, strict=True),
        start=1,
    ):
        if (
            type(record) is not dict
            or type(observation) is not dict
            or type(plan_item) is not dict
            or record.get("observation") != observation
        ):
            raise AssertionError(
                f"Rev physical record {ordinal} is not state-bound"
            )
        run = runs.get(observation.get("run_id"))
        receipt = receipts.get(observation.get("receipt_id"))
        stdout = artifacts.get(observation.get("stdout_artifact_id"))
        stderr = artifacts.get(observation.get("stderr_artifact_id"))
        if (
            run is None
            or receipt is None
            or stdout is None
            or stderr is None
            or run.id not in proof.evidence_run_ids
            or receipt.id not in proof.evidence_receipt_ids
        ):
            raise AssertionError(
                f"Rev physical record {ordinal} graph is incomplete"
            )
        request = _read_bound_json(
            challenge_root,
            record,
            "request",
            ordinal=ordinal,
        )
        result = _read_bound_json(
            challenge_root,
            record,
            "result",
            ordinal=ordinal,
        )
        validation = _read_bound_json(
            challenge_root,
            record,
            "validation",
            ordinal=ordinal,
        )
        if (
            frozenset(request) != _REQUEST_KEYS
            or request.get("argv") != ORACLE_ARGV
            or request.get("base_revision")
            != evidence.get("base_revision")
            or request.get("configuration_epoch")
            != evidence.get("configuration_epoch")
            or request.get("experiment_id") != proof.id
            or request.get("image_digest") != image_digest
            or request.get("kind") != "rev_acceptance_oracle"
            or request.get("network") != "none"
            or request.get("protocol") != REV_ACCEPTANCE_PROTOCOL
            or request.get("resource_request") != _RESOURCE_REQUEST
            or request.get("source_manifest_sha256")
            != evidence["source"]["manifest_sha256"]
            or request.get("source_sha256")
            != evidence["source"]["sha256"]
            or request.get("run_id") != run.id
            or request.get("contest_id") != state.contest_id
            or request.get("category") != state.category
            or request.get("challenge_id") != state.challenge_id
            or request.get("schema_version") != 1
            or type(request.get("created_at")) is not str
            or not request.get("created_at")
            or any(
                request.get(field) != plan_item.get(field)
                for field in (
                    "input_sha256",
                    "input_size_bytes",
                    "mutation_id",
                    "ordinal",
                    "phase",
                )
            )
            or frozenset(result) != _RESULT_KEYS
            or result.get("run_id") != run.id
            or result.get("contest_id") != state.contest_id
            or result.get("category") != state.category
            or result.get("challenge_id") != state.challenge_id
            or result.get("schema_version") != 1
            or result.get("status") != "completed"
            or result.get("rev_acceptance_observation") != observation
            or result.get("artifacts")
            != [stdout.to_dict(), stderr.to_dict()]
            or frozenset(validation) != _VALIDATION_KEYS
            or validation.get("run_id") != run.id
            or type(validation.get("validated_at")) is not str
            or not validation.get("validated_at")
            or validation.get("status") != "valid_transport"
            or validation.get("rev_acceptance_observation")
            != observation
            or observation.get("capture_complete") is not True
            or observation.get("clean_workspace") is not True
            or observation.get("network") != "none"
            or observation.get("timed_out") is not False
        ):
            raise AssertionError(
                f"Rev physical record {ordinal} is not exact"
            )
        for stream, artifact in (("stdout", stdout), ("stderr", stderr)):
            if (
                artifact.source_run_id != run.id
                or artifact.sha256 != observation.get(f"{stream}_sha256")
                or artifact.size
                != observation.get(f"{stream}_size_bytes")
            ):
                raise AssertionError(
                    f"Rev physical record {ordinal} {stream} is not bound"
                )
            _read_bound_artifact(
                challenge_root,
                artifact,
                maximum_bytes=REV_ACCEPTANCE_MAX_STREAM_BYTES,
                label=f"record {ordinal} {stream}",
            )
        ordered_runs.append(run)
        ordered_receipts.append(receipt)

    if (
        [item.id for item in ordered_runs] != proof.evidence_run_ids
        or [item.id for item in ordered_receipts]
        != proof.evidence_receipt_ids
    ):
        raise AssertionError("Rev physical execution ordering changed")
    return ordered_runs, ordered_receipts


def main() -> int:
    image_digest = validate_image_digest(_parse_args().image_digest)
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
        committed = ManagedOrchestrator(engine).run_cycle(identity)
        committed_revision = committed.revision
        state = engine.store.load(identity, recover=False)
        state.validate()
        validate_rev_acceptance_state_graph(state)
        verified_artifacts = engine.store.verify_artifacts(identity)
        if (
            state.revision != committed_revision
            or set(verified_artifacts)
            != {artifact.id for artifact in state.artifacts}
        ):
            raise AssertionError(
                "managed Rev StateStore reload or artifact validation failed"
            )
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
        proof_runs, proof_receipts = _validated_physical_rev_execution(
            state,
            proof,
            challenge_root=engine.store.challenge_paths(identity).root,
            image_digest=image_digest,
        )
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
