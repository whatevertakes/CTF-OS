#!/usr/bin/env python3
"""Exercise the Crypto and Misc ChallengeEngine hot paths in real Docker.

The release smoke is deliberately self-contained and local.  It opens one
temporary challenge per category, supplies one operator candidate, and invokes
the same public engine methods used by ``ctfos``.  No model API, remote target,
automatic challenge selection, or submission is involved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace

from ctf_os.capabilities import inspect_pinned_capabilities
from ctf_os.codex import Role
from ctf_os.config import EngineConfig, RuntimeConfig
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.crypto_metamorphic import (
    CRYPTO_METAMORPHIC_PROOF_PROTOCOL,
)
from ctf_os.engine.managed_oracle_preissue import (
    MANAGED_ORACLE_PREISSUE_PROTOCOL,
    MANAGED_ORACLE_PREISSUE_STATE_KEY,
)
from ctf_os.engine.misc_transform import (
    MISC_TRANSFORM_MAX_EVIDENCE_BYTES,
    MISC_TRANSFORM_MAX_OUTPUT_BYTES,
    MISC_TRANSFORM_MAX_STREAM_BYTES,
    MISC_TRANSFORM_PROTOCOL,
    misc_transform_canonical_json_bytes,
)
from ctf_os.images import validate_image_digest
from ctf_os.managed import ManagedOrchestrator
from ctf_os.models import (
    ArtifactReference,
    CandidateStatus,
    ChallengeIdentity,
    FlagCandidate,
    RunOrigin,
    RunStatus,
)
from ctf_os.sandbox.files import read_bounded_regular
from ctf_os.schema import STATE_SCHEMA_VERSION


CRYPTO_CANDIDATE = "KCTF{docker-crypto-metamorphic-hotpath}"


def _rsa_parameter_document(
    *,
    modulus: int,
    exponent: int,
    plaintext: bytes,
    rounds: int,
) -> bytes:
    return (
        json.dumps(
            {
                "N": modulus,
                "ciphertexts": [
                    pow(value, exponent, modulus)
                    for value in plaintext
                ],
                "e": exponent,
                "rounds": rounds,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


CRYPTO_VARIANT_OUTPUT = (
    b"metamorphic-variant:"
    + b"x"
    * (
        len(CRYPTO_CANDIDATE.encode("utf-8"))
        - len(b"metamorphic-variant:")
    )
)
CRYPTO_ORIGINAL = _rsa_parameter_document(
    modulus=61 * 53,
    exponent=17,
    plaintext=CRYPTO_CANDIDATE.encode("utf-8"),
    rounds=1,
)
CRYPTO_VARIANT = _rsa_parameter_document(
    modulus=67 * 71,
    exponent=17,
    plaintext=CRYPTO_VARIANT_OUTPUT,
    rounds=2,
)

MISC_CANDIDATE = "KCTF{docker-misc-transform-hotpath}"
MISC_SOURCE = b"immutable misc docker input\n"
_CRYPTO_PROOF_RESULT_KEYS = frozenset(
    {
        "candidate",
        "failures",
        "passed",
        "policy_mode",
        "required_attempts",
        "run_ids",
        "source_manifest_sha256",
        "successful_attempts",
        "total_attempts",
    }
)
_CRYPTO_BINDING_KEYS = frozenset(
    {
        "artifact_id",
        "evaluation",
        "evaluation_sha256",
        "oracle_authority",
        "oracle_preissue_id",
        "passed",
        "plan_sha256",
        "proof_result",
        "protocol",
        "run_ids",
    }
)
_CRYPTO_EVALUATION_KEYS = frozenset(
    {
        "candidate_sha256",
        "failure_codes",
        "observations",
        "oracle_artifact_sha256",
        "passed",
        "plan",
        "protocol",
        "runtime_fingerprint_sha256",
        "schema_version",
        "solver_artifact_sha256",
        "source_manifest_sha256",
    }
)
_CRYPTO_PLAN_KEYS = frozenset({"attempts", "cases", "protocol"})
_CRYPTO_ATTEMPT_KEYS = frozenset(
    {
        "case_id",
        "expected_output_sha256",
        "expected_output_size_bytes",
        "mutation_id",
        "ordinal",
        "parameters_sha256",
        "parameters_size_bytes",
    }
)
_CRYPTO_OBSERVATION_KEYS = frozenset(
    {
        "capture_complete",
        "capture_error_present",
        "case_id",
        "clean_workspace",
        "ctfwrap_exit_code",
        "mutation_id",
        "oracle_artifact_sha256",
        "orchestration_status",
        "ordinal",
        "parameters_sha256",
        "parameters_size_bytes",
        "result_artifact_id",
        "result_artifact_sha256",
        "result_artifact_size_bytes",
        "run_id",
        "runner_exit_code",
        "runtime_fingerprint_sha256",
        "solver_artifact_sha256",
        "source_manifest_sha256",
        "target_exit_code",
        "timed_out",
        "truncated",
        "truncation_known",
    }
)
_CRYPTO_REQUEST_KEYS = frozenset(
    {
        "attempt",
        "base_revision",
        "candidate_id",
        "category",
        "challenge_id",
        "command",
        "configuration_epoch",
        "contest_id",
        "created_at",
        "image_reference",
        "kind",
        "network_target",
        "oracle_artifact_sha256",
        "plan_sha256",
        "protocol",
        "runtime_fingerprint_sha256",
        "run_id",
        "schema_version",
        "solver_sha256",
        "source_manifest_sha256",
    }
)
_CRYPTO_RESULT_KEYS = frozenset(
    {
        "artifacts",
        "category",
        "challenge_id",
        "contest_id",
        "duration_ms",
        "exit_code",
        "observation",
        "run_id",
        "schema_version",
        "status",
        "timed_out",
    }
)
_CRYPTO_VALIDATION_KEYS = frozenset(
    {
        "attempt_ordinal",
        "ok",
        "plan_sha256",
        "protocol",
        "run_id",
        "validated_at",
    }
)
_CRYPTO_RUN_DOCUMENT_MAX_BYTES = 1_048_576
_CRYPTO_STREAM_MAX_BYTES = 1_048_576
_MISC_RUN_DOCUMENT_MAX_BYTES = 1_048_576
_MISC_BINDING_KEYS = frozenset(
    {
        "artifact_id",
        "automatic_submission_authorized",
        "candidate_sha256",
        "evaluation",
        "evaluation_sha256",
        "misc_evaluation_id",
        "oracle_authority",
        "oracle_control_run_ids",
        "oracle_control_status",
        "oracle_negative_control_passed",
        "oracle_preissue_id",
        "passed",
        "plan_sha256",
        "protocol",
        "run_ids",
        "source_manifest_sha256",
    }
)
_MISC_REQUEST_COMMON_KEYS = frozenset(
    {
        "base_revision",
        "candidate_id",
        "category",
        "challenge_id",
        "command",
        "contest_id",
        "created_at",
        "image_reference",
        "kind",
        "misc_evaluation_id",
        "network_target",
        "ordinal",
        "phase",
        "plan_sha256",
        "protocol",
        "run_id",
        "schema_version",
        "source_manifest_sha256",
    }
)
_MISC_RESULT_COMMON_KEYS = frozenset(
    {
        "artifacts",
        "category",
        "challenge_id",
        "contest_id",
        "exit_code",
        "ordinal",
        "phase",
        "plan_sha256",
        "run_id",
        "schema_version",
        "status",
        "timed_out",
    }
)
_MISC_VALIDATION_KEYS = frozenset(
    {
        "ok",
        "ordinal",
        "phase",
        "plan_sha256",
        "protocol",
        "run_id",
        "validated_at",
    }
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Require the Crypto 3+3 metamorphic gate and Misc transform DAG "
            "plus 3-replay oracle to pass through the real pinned image."
        )
    )
    parser.add_argument(
        "--image-digest",
        required=True,
        help="exact local sha256:<64 lowercase hex> Docker image ID",
    )
    return parser.parse_args()


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


def _add_candidate(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    candidate_id: str,
    value: str,
) -> None:
    def mutate(state) -> None:
        state.candidates.append(
            FlagCandidate(id=candidate_id, value=value)
        )

    engine.store.update(identity, mutate)


def _capability(_digest: str) -> dict[str, object]:
    return {"ok": True, "schema_version": 2, "capabilities": {}}


def _execute_managed_builder_action(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    action: dict[str, object],
    payloads: dict[str, bytes],
    extra_write_locators: tuple[str, ...] = (),
) -> tuple[object, object]:
    """Drive the real Builder publish/register/dispatch path without a model."""

    orchestrator = ManagedOrchestrator(
        engine,
        capability_probe=_capability,
    )
    _state, session_id = orchestrator._reserve_session(identity, None)
    _state, cycle = orchestrator._reserve_cycle(identity, session_id)
    _state, wave, role_runs = orchestrator._reserve_wave(
        identity,
        session_id,
        cycle.id,
        "attack",
    )
    builder_run_id = role_runs[Role.BUILDER]
    paths = engine.store.challenge_paths(identity)
    run_workspace = (
        engine.store.run_paths(identity, run_id=builder_run_id).root
        / "workspace"
    )
    run_workspace.mkdir(parents=True)
    snapshots = paths.artifacts / "snapshots"
    snapshots.mkdir(parents=True, exist_ok=True)

    records: list[tuple[str, str, bytes, str]] = []
    for ordinal, (locator, payload) in enumerate(
        sorted(payloads.items()),
        start=1,
    ):
        staged = run_workspace / locator
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(payload)
        artifact_id = f"A-{builder_run_id}-release-{ordinal}"
        relative = f"artifacts/snapshots/{artifact_id}.bin"
        snapshot = paths.root / relative
        snapshot.write_bytes(payload)
        snapshot.chmod(0o400)
        records.append((artifact_id, relative, payload, locator))

    def seed(state) -> None:
        run = next(
            item for item in state.runs if item.id == builder_run_id
        )
        run.status = RunStatus.COMPLETED
        run.result_path = f"runs/{builder_run_id}/result.json"
        run.validation_path = f"runs/{builder_run_id}/validation.json"
        run.extra["semantic_merge"] = True
        for artifact_id, relative, payload, locator in records:
            state.artifacts.append(
                ArtifactReference(
                    id=artifact_id,
                    path=relative,
                    sha256=hashlib.sha256(payload).hexdigest(),
                    source_run_id=builder_run_id,
                    size=len(payload),
                    extra={
                        "reported_locator": locator,
                        "purpose": "managed release gate input",
                    },
                )
            )

    engine.store.update(identity, seed)
    output_actions = [
        {
            "kind": "write_artifact",
            "description": "publish referenced deterministic tool",
            "artifact_path": locator,
        }
        for locator in extra_write_locators
    ]
    output_actions.append(action)
    result = SimpleNamespace(
        invocation=SimpleNamespace(
            role=Role.BUILDER,
            run_id=builder_run_id,
            contract_version=2,
        ),
        output={"hypotheses": [], "actions": output_actions},
        attempts=(SimpleNamespace(),),
    )
    publication = orchestrator._apply_builder_publishes(
        identity,
        wave,
        (result,),
    )
    if publication.rejection is not None:
        raise AssertionError(publication.rejection)
    registration = orchestrator._register_typed_gate_actions(
        identity,
        wave,
        (result,),
    )
    if (
        registration.rejection_code is not None
        or len(registration.experiment_ids) != 1
    ):
        raise AssertionError(
            registration.rejection_code or "typed gate was not registered"
        )
    experiment_id = registration.experiment_ids[0]
    orchestrator._mark_action_selection(
        identity,
        session_id,
        cycle.id,
        (experiment_id,),
    )
    final = orchestrator._execute_selected_actions(
        identity,
        (experiment_id,),
        record_stall=False,
    )
    experiment = next(
        item for item in final.experiments if item.id == experiment_id
    )
    return final, experiment


def _read_crypto_run_document(
    challenge_root: Path,
    locator: str | None,
    *,
    label: str,
) -> dict[str, object]:
    if type(locator) is not str or not locator:
        raise AssertionError(f"Crypto {label} path is absent")
    try:
        relative = Path(locator)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ValueError("run document path is not canonical")
        target = challenge_root.joinpath(*relative.parts)
        metadata = target.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size < 0
            or metadata.st_size > _CRYPTO_RUN_DOCUMENT_MAX_BYTES
        ):
            raise ValueError("run document is not a bounded regular file")
        observed = target.read_bytes()
        if len(observed) != metadata.st_size:
            raise ValueError("run document changed during inventory")
        payload = read_bounded_regular(
            challenge_root,
            locator,
            maximum_bytes=_CRYPTO_RUN_DOCUMENT_MAX_BYTES,
            expected_sha256=hashlib.sha256(observed).hexdigest(),
            expected_size=len(observed),
        )
        value = json.loads(payload)
    except (OSError, UnicodeError, ValueError) as error:
        raise AssertionError(
            f"Crypto {label} is not a bounded canonical JSON document"
        ) from error
    if type(value) is not dict:
        raise AssertionError(f"Crypto {label} is not an object")
    return value


def _read_misc_run_document(
    challenge_root: Path,
    locator: str | None,
    *,
    label: str,
) -> dict[str, object]:
    if type(locator) is not str or not locator:
        raise AssertionError(f"Misc {label} path is absent")
    try:
        relative = Path(locator)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ValueError("run document path is not canonical")
        target = challenge_root.joinpath(*relative.parts)
        metadata = target.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size < 0
            or metadata.st_size > _MISC_RUN_DOCUMENT_MAX_BYTES
        ):
            raise ValueError("run document is not a bounded regular file")
        observed = target.read_bytes()
        if len(observed) != metadata.st_size:
            raise ValueError("run document changed during inventory")
        payload = read_bounded_regular(
            challenge_root,
            locator,
            maximum_bytes=_MISC_RUN_DOCUMENT_MAX_BYTES,
            expected_sha256=hashlib.sha256(observed).hexdigest(),
            expected_size=len(observed),
        )
        value = json.loads(payload)
    except (OSError, UnicodeError, ValueError) as error:
        raise AssertionError(
            f"Misc {label} is not a bounded canonical JSON document"
        ) from error
    if type(value) is not dict:
        raise AssertionError(f"Misc {label} is not an object")
    return value


def _validated_misc_execution(
    final,
    candidate,
    binding: object,
    *,
    challenge_root: Path,
    image_digest: str,
) -> tuple[list[object], dict[str, int]]:
    """Re-derive the release result from five physical Misc executions."""

    if (
        type(binding) is not dict
        or frozenset(binding) != _MISC_BINDING_KEYS
        or binding.get("protocol") != MISC_TRANSFORM_PROTOCOL
        or binding.get("oracle_authority")
        != MANAGED_ORACLE_PREISSUE_PROTOCOL
        or binding.get("passed") is not True
        or binding.get("automatic_submission_authorized") is not False
        or binding.get("oracle_control_status") != "passed"
        or binding.get("oracle_negative_control_passed") is not True
        or binding.get("candidate_sha256")
        != hashlib.sha256(candidate.value.encode("utf-8")).hexdigest()
        or binding.get("source_manifest_sha256")
        != final.metadata.get("source_manifest_sha256")
    ):
        raise AssertionError("Misc managed proof binding is absent")
    evaluation = binding.get("evaluation")
    logical_run_ids = binding.get("run_ids")
    control_run_ids = binding.get("oracle_control_run_ids")
    evaluation_id = binding.get("misc_evaluation_id")
    plan_sha256 = binding.get("plan_sha256")
    preissue_id = binding.get("oracle_preissue_id")
    if (
        type(evaluation) is not dict
        or evaluation.get("protocol") != MISC_TRANSFORM_PROTOCOL
        or evaluation.get("passed") is not True
        or evaluation.get("failure_codes") != []
        or evaluation.get("plan_sha256") != plan_sha256
        or type(logical_run_ids) is not list
        or len(logical_run_ids) != 4
        or len(set(logical_run_ids)) != 4
        or type(control_run_ids) is not list
        or len(control_run_ids) != 1
        or len(set(control_run_ids)) != 1
        or set(logical_run_ids) & set(control_run_ids)
        or any(
            type(run_id) is not str or not run_id
            for run_id in [*logical_run_ids, *control_run_ids]
        )
        or type(evaluation_id) is not str
        or not evaluation_id
        or type(plan_sha256) is not str
        or type(preissue_id) is not str
        or not preissue_id
    ):
        raise AssertionError("Misc evaluation graph is incomplete")

    canonical_evaluation = misc_transform_canonical_json_bytes(evaluation)
    if (
        binding.get("evaluation_sha256")
        != hashlib.sha256(canonical_evaluation).hexdigest()
    ):
        raise AssertionError("Misc evaluation commitment is inconsistent")
    artifacts_by_id = {item.id: item for item in final.artifacts}
    if len(artifacts_by_id) != len(final.artifacts):
        raise AssertionError("Misc state contains duplicate artifact IDs")
    evaluation_artifact = artifacts_by_id.get(binding.get("artifact_id"))
    if (
        evaluation_artifact is None
        or evaluation_artifact.sha256
        != binding.get("evaluation_sha256")
        or evaluation_artifact.size != len(canonical_evaluation)
    ):
        raise AssertionError("Misc evaluation artifact is not bound")
    try:
        observed_evaluation = read_bounded_regular(
            challenge_root,
            evaluation_artifact.path,
            maximum_bytes=MISC_TRANSFORM_MAX_EVIDENCE_BYTES,
            expected_sha256=evaluation_artifact.sha256,
            expected_size=evaluation_artifact.size,
        )
    except (OSError, ValueError) as error:
        raise AssertionError(
            "Misc evaluation artifact does not match state"
        ) from error
    if observed_evaluation != canonical_evaluation:
        raise AssertionError("Misc physical evaluation changed")

    selected_ids = set(logical_run_ids) | set(control_run_ids)
    physical_runs = [item for item in final.runs if item.id in selected_ids]
    phases = [item.extra.get("phase") for item in physical_runs]
    if (
        len(physical_runs) != 5
        or phases
        != ["transform", "oracle-control", "reverse", "reverse", "reverse"]
        or [item.id for item in physical_runs if item.extra.get("phase") != "oracle-control"]
        != logical_run_ids
        or [item.id for item in physical_runs if item.extra.get("phase") == "oracle-control"]
        != control_run_ids
    ):
        raise AssertionError("Misc physical run matrix is incomplete")

    expected_transform_command = [
        "/usr/bin/python3",
        "/work/tool/transform.py",
        "/work/inputs/001.bin",
    ]
    expected_verifier_command = [
        "/usr/bin/python3",
        "/work/oracle/verifier.py",
        "/work/candidate/candidate.bin",
        "/work/sources/001.bin",
    ]
    counts = {"transform": 0, "oracle-control": 0, "reverse": 0}
    for run in physical_runs:
        phase = run.extra.get("phase")
        ordinal = run.extra.get("ordinal")
        if (
            phase not in counts
            or type(ordinal) is not int
            or run.status is not RunStatus.COMPLETED
            or run.origin is not RunOrigin.PROOF
            or run.configuration_epoch != final.configuration_epoch
            or run.role != "misc_transform"
            or run.request_path != f"runs/{run.id}/request.json"
            or run.result_path != f"runs/{run.id}/result.json"
            or run.validation_path != f"runs/{run.id}/validation.json"
            or run.extra.get("misc_transform_protocol")
            != MISC_TRANSFORM_PROTOCOL
            or run.extra.get("misc_evaluation_id") != evaluation_id
            or run.extra.get("plan_sha256") != plan_sha256
        ):
            raise AssertionError(
                f"Misc physical {phase!s} run is not state-bound"
            )
        request = _read_misc_run_document(
            challenge_root,
            run.request_path,
            label=f"{phase} request",
        )
        result = _read_misc_run_document(
            challenge_root,
            run.result_path,
            label=f"{phase} result",
        )
        validation = _read_misc_run_document(
            challenge_root,
            run.validation_path,
            label=f"{phase} validation",
        )
        phase_request_keys = {
            "transform": {"step_id"},
            "oracle-control": {
                "negative_control_sha256",
                "oracle_authority",
                "oracle_preissue_id",
                "verifier_id",
            },
            "reverse": {
                "oracle_authority",
                "oracle_preissue_id",
                "verifier_id",
            },
        }[phase]
        phase_result_keys = {
            "transform": {"output_artifact", "step_id"},
            "oracle-control": {"negative_control_rejected"},
            "reverse": {"verifier_accepts"},
        }[phase]
        if (
            frozenset(request)
            != _MISC_REQUEST_COMMON_KEYS | phase_request_keys
            or request.get("base_revision") != run.base_revision
            or request.get("candidate_id") != candidate.id
            or request.get("contest_id") != final.contest_id
            or request.get("category") != final.category
            or request.get("challenge_id") != final.challenge_id
            or request.get("run_id") != run.id
            or request.get("schema_version") != 1
            or type(request.get("created_at")) is not str
            or not request.get("created_at")
            or request.get("kind") != "misc_transform"
            or request.get("protocol") != MISC_TRANSFORM_PROTOCOL
            or request.get("misc_evaluation_id") != evaluation_id
            or request.get("plan_sha256") != plan_sha256
            or request.get("phase") != phase
            or request.get("ordinal") != ordinal
            or request.get("network_target") is not None
            or request.get("source_manifest_sha256")
            != binding.get("source_manifest_sha256")
            or request.get("image_reference") != image_digest
            or request.get("command")
            != (
                expected_transform_command
                if phase == "transform"
                else expected_verifier_command
            )
            or frozenset(result)
            != _MISC_RESULT_COMMON_KEYS | phase_result_keys
            or result.get("contest_id") != final.contest_id
            or result.get("category") != final.category
            or result.get("challenge_id") != final.challenge_id
            or result.get("run_id") != run.id
            or result.get("schema_version") != 1
            or result.get("phase") != phase
            or result.get("ordinal") != ordinal
            or result.get("plan_sha256") != plan_sha256
            or result.get("timed_out") is not False
            or frozenset(validation) != _MISC_VALIDATION_KEYS
            or validation.get("run_id") != run.id
            or type(validation.get("validated_at")) is not str
            or not validation.get("validated_at")
            or validation.get("ok") is not True
            or validation.get("phase") != phase
            or validation.get("ordinal") != ordinal
            or validation.get("protocol") != MISC_TRANSFORM_PROTOCOL
            or validation.get("plan_sha256") != plan_sha256
        ):
            raise AssertionError(
                f"Misc physical {phase} evidence is not exact"
            )

        record = run.extra.get("misc_transform_record")
        if phase == "transform":
            if (
                request.get("step_id") != run.extra.get("step_id")
                or result.get("step_id") != run.extra.get("step_id")
                or result.get("status") != "completed"
                or result.get("exit_code") != 0
                or type(record) is not dict
                or record.get("run_id") != run.id
                or record.get("accepted") is not True
                or record.get("clean_workspace") is not True
                or record.get("network_denied") is not True
                or record.get("target_exit_code") != 0
                or record.get("runner_exit_code") != 0
                or record.get("ctfwrap_exit_code") != 0
                or record.get("timed_out") is not False
                or record.get("orchestration_status") != "completed"
                or result.get("output_artifact")
                != record.get("output_artifact")
            ):
                raise AssertionError(
                    "Misc physical transform did not produce the bound node"
                )
            expected_artifact_ids = [
                record["stdout"]["artifact_id"],
                record["stderr"]["artifact_id"],
                record["output_artifact"]["artifact_id"],
            ]
        elif phase == "oracle-control":
            if (
                request.get("oracle_authority")
                != MANAGED_ORACLE_PREISSUE_PROTOCOL
                or request.get("oracle_preissue_id") != preissue_id
                or request.get("verifier_id") != run.extra.get("verifier_id")
                or type(request.get("negative_control_sha256")) is not str
                or len(request["negative_control_sha256"]) != 64
                or result.get("status") != "failed"
                or type(result.get("exit_code")) is not int
                or result.get("exit_code") == 0
                or result.get("negative_control_rejected") is not True
                or run.extra.get("negative_control_rejected") is not True
            ):
                raise AssertionError(
                    "Misc physical negative control was not rejected"
                )
            control_streams = {
                artifact.extra.get("stream"): artifact.id
                for artifact in final.artifacts
                if artifact.source_run_id == run.id
                and artifact.extra.get("kind") == "misc_transform_stream"
            }
            if set(control_streams) != {"stdout", "stderr"}:
                raise AssertionError(
                    "Misc physical negative-control streams are incomplete"
                )
            expected_artifact_ids = [
                control_streams["stdout"],
                control_streams["stderr"],
            ]
        else:
            if (
                request.get("oracle_authority")
                != MANAGED_ORACLE_PREISSUE_PROTOCOL
                or request.get("oracle_preissue_id") != preissue_id
                or request.get("verifier_id") != run.extra.get("verifier_id")
                or result.get("status") != "completed"
                or result.get("exit_code") != 0
                or result.get("verifier_accepts") is not True
                or type(record) is not dict
                or record.get("run_id") != run.id
                or record.get("accepted") is not True
                or record.get("clean_workspace") is not True
                or record.get("network_denied") is not True
                or record.get("target_exit_code") != 0
                or record.get("runner_exit_code") != 0
                or record.get("ctfwrap_exit_code") != 0
                or record.get("timed_out") is not False
                or record.get("orchestration_status") != "completed"
            ):
                raise AssertionError(
                    "Misc physical reverse oracle did not accept"
                )
            expected_artifact_ids = [
                record["stdout"]["artifact_id"],
                record["stderr"]["artifact_id"],
                record["result_artifact"]["artifact_id"],
            ]

        result_artifacts = result.get("artifacts")
        if (
            type(result_artifacts) is not list
            or len(result_artifacts) != len(expected_artifact_ids)
            or any(
                type(reference) is not dict
                or reference.get("id") != artifact_id
                or artifact_id not in artifacts_by_id
                or reference != artifacts_by_id[artifact_id].to_dict()
                or artifacts_by_id[artifact_id].source_run_id != run.id
                for reference, artifact_id in zip(
                    result_artifacts,
                    expected_artifact_ids,
                    strict=True,
                )
            )
        ):
            raise AssertionError(
                f"Misc physical {phase} artifact graph is not exact"
            )
        for artifact_id in expected_artifact_ids:
            artifact = artifacts_by_id[artifact_id]
            maximum = (
                MISC_TRANSFORM_MAX_STREAM_BYTES
                if artifact.extra.get("kind") == "misc_transform_stream"
                else MISC_TRANSFORM_MAX_OUTPUT_BYTES
            )
            try:
                read_bounded_regular(
                    challenge_root,
                    artifact.path,
                    maximum_bytes=maximum,
                    expected_sha256=artifact.sha256,
                    expected_size=artifact.size,
                )
            except (OSError, ValueError) as error:
                raise AssertionError(
                    f"Misc physical {phase} artifact does not match state"
                ) from error
        counts[phase] += 1

    if counts != {"transform": 1, "oracle-control": 1, "reverse": 3}:
        raise AssertionError("Misc physical execution counts are incomplete")
    return physical_runs, counts


def _validated_crypto_execution(
    final,
    candidate,
    binding: object,
    *,
    challenge_root: Path,
    image_digest: str,
    runtime: str,
) -> tuple[list[object], int]:
    """Cross-check state commitments against six physical executions."""

    if runtime not in {"python", "sage"}:
        raise AssertionError("Crypto release runtime is invalid")
    if (
        type(binding) is not dict
        or frozenset(binding) != _CRYPTO_BINDING_KEYS
    ):
        raise AssertionError("Crypto proof binding is absent")
    proof_result = binding.get("proof_result")
    run_ids = binding.get("run_ids")
    evaluation = binding.get("evaluation")
    plan = (
        evaluation.get("plan")
        if type(evaluation) is dict
        else None
    )
    attempts = plan.get("attempts") if type(plan) is dict else None
    observations = (
        evaluation.get("observations")
        if type(evaluation) is dict
        else None
    )
    source_manifest_sha256 = final.metadata.get(
        "source_manifest_sha256"
    )
    if (
        type(proof_result) is not dict
        or frozenset(proof_result) != _CRYPTO_PROOF_RESULT_KEYS
        or type(evaluation) is not dict
        or frozenset(evaluation) != _CRYPTO_EVALUATION_KEYS
        or type(plan) is not dict
        or frozenset(plan) != _CRYPTO_PLAN_KEYS
        or plan.get("protocol") != CRYPTO_METAMORPHIC_PROOF_PROTOCOL
        or type(attempts) is not list
        or len(attempts) != 6
        or any(
            type(attempt) is not dict
            or frozenset(attempt) != _CRYPTO_ATTEMPT_KEYS
            for attempt in attempts
        )
        or type(observations) is not list
        or len(observations) != 6
        or any(
            type(observation) is not dict
            or frozenset(observation) != _CRYPTO_OBSERVATION_KEYS
            for observation in observations
        )
        or type(run_ids) is not list
        or len(run_ids) != 6
        or len(set(run_ids)) != 6
        or any(type(run_id) is not str or not run_id for run_id in run_ids)
        or list(candidate.proof_run_ids) != run_ids
        or proof_result.get("run_ids") != run_ids
        or binding.get("passed") is not True
        or binding.get("protocol")
        != CRYPTO_METAMORPHIC_PROOF_PROTOCOL
        or binding.get("oracle_authority")
        != MANAGED_ORACLE_PREISSUE_PROTOCOL
        or evaluation.get("passed") is not True
        or evaluation.get("failure_codes") != []
        or evaluation.get("protocol")
        != CRYPTO_METAMORPHIC_PROOF_PROTOCOL
        or evaluation.get("schema_version") != 1
        or evaluation.get("candidate_sha256")
        != hashlib.sha256(candidate.value.encode("utf-8")).hexdigest()
        or evaluation.get("source_manifest_sha256")
        != source_manifest_sha256
        or binding.get("evaluation_sha256")
        != hashlib.sha256(
            (
                json.dumps(
                    evaluation,
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("ascii")
        ).hexdigest()
        or binding.get("plan_sha256")
        != hashlib.sha256(
            (
                json.dumps(
                    plan,
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("ascii")
        ).hexdigest()
        or proof_result.get("passed") is not True
        or proof_result.get("candidate") != candidate.value
        or proof_result.get("policy_mode")
        != CRYPTO_METAMORPHIC_PROOF_PROTOCOL
        or proof_result.get("source_manifest_sha256")
        != source_manifest_sha256
        or proof_result.get("successful_attempts") != 6
        or proof_result.get("required_attempts") != 6
        or proof_result.get("total_attempts") != 6
        or proof_result.get("failures") != []
    ):
        raise AssertionError(
            "Crypto ProofResult does not describe six successful attempts"
        )

    runs_by_id = {
        item.id: item for item in final.runs if item.id in set(run_ids)
    }
    if len(runs_by_id) != 6:
        raise AssertionError("Crypto physical proof runs are incomplete")
    runs = [runs_by_id[run_id] for run_id in run_ids]
    plan_sha256 = binding.get("plan_sha256")
    configuration_epoch = final.configuration_epoch
    expected_command = (
        [
            "python3",
            "/work/oracle/solver.py",
            "/work/oracle/parameters.json",
        ]
        if runtime == "python"
        else [
            "sage",
            "/work/oracle/solver.sage",
            "/work/oracle/parameters.json",
        ]
    )
    artifacts = list(final.artifacts)
    if len({item.id for item in artifacts}) != len(artifacts):
        raise AssertionError("Crypto state contains duplicate artifact IDs")
    successful_attempts = 0
    for ordinal, run in enumerate(runs, start=1):
        expected_attempt = attempts[ordinal - 1]
        committed_observation = observations[ordinal - 1]
        expected_run_extra = {
            "attempt_ordinal": ordinal,
            "crypto_metamorphic_protocol": (
                CRYPTO_METAMORPHIC_PROOF_PROTOCOL
            ),
            "observation": committed_observation,
            "plan_sha256": plan_sha256,
        }
        if (
            run.status is not RunStatus.COMPLETED
            or run.origin is not RunOrigin.PROOF
            or run.configuration_epoch != configuration_epoch
            or run.role != "crypto_metamorphic_proof"
            or run.request_path != f"runs/{run.id}/request.json"
            or run.result_path != f"runs/{run.id}/result.json"
            or run.validation_path
            != f"runs/{run.id}/validation.json"
            or run.extra != expected_run_extra
        ):
            raise AssertionError(
                f"Crypto physical run {ordinal} is not completed and bound"
            )
        request = _read_crypto_run_document(
            challenge_root,
            run.request_path,
            label=f"run {ordinal} request",
        )
        result = _read_crypto_run_document(
            challenge_root,
            run.result_path,
            label=f"run {ordinal} result",
        )
        validation = _read_crypto_run_document(
            challenge_root,
            run.validation_path,
            label=f"run {ordinal} validation",
        )
        attempt = request.get("attempt")
        observation = result.get("observation")
        if (
            frozenset(request) != _CRYPTO_REQUEST_KEYS
            or request.get("base_revision") != run.base_revision
            or request.get("contest_id") != final.contest_id
            or request.get("category") != final.category
            or request.get("challenge_id") != final.challenge_id
            or request.get("run_id") != run.id
            or request.get("schema_version") != 1
            or type(request.get("created_at")) is not str
            or not request.get("created_at")
            or request.get("kind") != "crypto_metamorphic_proof"
            or request.get("candidate_id") != candidate.id
            or request.get("protocol")
            != CRYPTO_METAMORPHIC_PROOF_PROTOCOL
            or request.get("plan_sha256") != plan_sha256
            or request.get("command") != expected_command
            or request.get("network_target") is not None
            or request.get("image_reference") != image_digest
            or request.get("source_manifest_sha256")
            != source_manifest_sha256
            or request.get("solver_sha256")
            != evaluation.get("solver_artifact_sha256")
            or request.get("runtime_fingerprint_sha256")
            != evaluation.get("runtime_fingerprint_sha256")
            or request.get("oracle_artifact_sha256")
            != evaluation.get("oracle_artifact_sha256")
            or request.get("configuration_epoch")
            != configuration_epoch
            or attempt != expected_attempt
            or frozenset(result) != _CRYPTO_RESULT_KEYS
            or result.get("contest_id") != final.contest_id
            or result.get("category") != final.category
            or result.get("challenge_id") != final.challenge_id
            or result.get("run_id") != run.id
            or result.get("schema_version") != 1
            or result.get("status") != "completed"
            or result.get("exit_code") != 0
            or result.get("timed_out") is not False
            or type(result.get("duration_ms")) is not int
            or result.get("duration_ms", -1) < 0
            or observation != committed_observation
            or observation != run.extra.get("observation")
            or frozenset(validation) != _CRYPTO_VALIDATION_KEYS
            or validation.get("run_id") != run.id
            or type(validation.get("validated_at")) is not str
            or not validation.get("validated_at")
            or validation.get("ok") is not True
            or validation.get("protocol")
            != CRYPTO_METAMORPHIC_PROOF_PROTOCOL
            or validation.get("plan_sha256") != plan_sha256
            or validation.get("attempt_ordinal") != ordinal
        ):
            raise AssertionError(
                f"Crypto physical run {ordinal} evidence is not successful"
            )

        assert isinstance(observation, dict)
        if (
            observation.get("run_id") != run.id
            or observation.get("ordinal") != ordinal
            or any(
                observation.get(field) != expected_attempt.get(field)
                for field in (
                    "case_id",
                    "mutation_id",
                    "parameters_sha256",
                    "parameters_size_bytes",
                )
            )
            or observation.get("source_manifest_sha256")
            != source_manifest_sha256
            or observation.get("solver_artifact_sha256")
            != evaluation.get("solver_artifact_sha256")
            or observation.get("runtime_fingerprint_sha256")
            != evaluation.get("runtime_fingerprint_sha256")
            or observation.get("oracle_artifact_sha256")
            != evaluation.get("oracle_artifact_sha256")
            or observation.get("clean_workspace") is not True
            or observation.get("target_exit_code") != 0
            or observation.get("runner_exit_code") != 0
            or observation.get("ctfwrap_exit_code") != 0
            or observation.get("timed_out") is not False
            or observation.get("orchestration_status") != "completed"
            or observation.get("capture_complete") is not True
            or observation.get("capture_error_present") is not False
            or observation.get("truncation_known") is not True
            or observation.get("truncated") is not False
        ):
            raise AssertionError(
                f"Crypto physical run {ordinal} provenance is not successful"
            )

        linked = [
            artifact
            for artifact in artifacts
            if artifact.source_run_id == run.id
        ]
        streams = {
            artifact.extra.get("stream"): artifact
            for artifact in linked
            if artifact.extra.get("stream") in {"stdout", "stderr"}
        }
        expected_stream_extra = {
            stream: {
                "attempt_ordinal": ordinal,
                "context_visibility": "engine_private",
                "kind": "crypto_metamorphic_stream",
                "plan_sha256": plan_sha256,
                "protocol": CRYPTO_METAMORPHIC_PROOF_PROTOCOL,
                "stream": stream,
            }
            for stream in ("stdout", "stderr")
        }
        if (
            len(linked) != 2
            or len(streams) != 2
            or set(streams) != {"stdout", "stderr"}
            or any(
                artifact.extra != expected_stream_extra[stream]
                or type(artifact.size) is not int
                or artifact.size < 0
                or artifact.size > _CRYPTO_STREAM_MAX_BYTES
                for stream, artifact in streams.items()
            )
            or result.get("artifacts")
            != [
                streams["stdout"].to_dict(),
                streams["stderr"].to_dict(),
            ]
        ):
            raise AssertionError(
                f"Crypto physical run {ordinal} stream graph is not exact"
            )

        for stream in ("stdout", "stderr"):
            artifact = streams[stream]
            try:
                read_bounded_regular(
                    challenge_root,
                    artifact.path,
                    maximum_bytes=_CRYPTO_STREAM_MAX_BYTES,
                    expected_sha256=artifact.sha256,
                    expected_size=artifact.size,
                )
            except (OSError, ValueError) as error:
                raise AssertionError(
                    f"Crypto physical run {ordinal} {stream} artifact "
                    "does not match state"
                ) from error

        stdout = streams["stdout"]
        if (
            observation.get("result_artifact_id") != stdout.id
            or observation.get("result_artifact_sha256") != stdout.sha256
            or observation.get("result_artifact_size_bytes") != stdout.size
            or stdout.sha256
            != expected_attempt.get("expected_output_sha256")
            or stdout.size
            != expected_attempt.get("expected_output_size_bytes")
        ):
            raise AssertionError(
                f"Crypto physical run {ordinal} stdout is not the "
                "planned result"
            )
        successful_attempts += 1

    if (
        successful_attempts != 6
        or proof_result.get("successful_attempts")
        != successful_attempts
        or proof_result.get("run_ids")
        != [observation["run_id"] for observation in observations]
    ):
        raise AssertionError(
            "Crypto ProofResult contradicts physical execution"
        )
    return runs, successful_attempts


def _crypto(
    root: Path,
    image_digest: str,
    *,
    runtime: str,
) -> dict[str, object]:
    if runtime not in {"python", "sage"}:
        raise ValueError("release smoke runtime must be python or sage")
    engine = _engine(root, image_digest)
    identity = ChallengeIdentity(
        "release-smoke",
        "crypto",
        f"metamorphic-hotpath-{runtime}",
    )
    incoming = engine.challenge_input(identity)
    incoming.mkdir(parents=True)
    (incoming / "task.py").write_text(
        "N = 3233\nciphertext = 2790\ne = 17\n",
        encoding="utf-8",
    )
    state = engine.add_challenge(
        identity,
        prompt="release smoke only",
        state_schema_version=STATE_SCHEMA_VERSION,
    )
    workspace = engine._workspace(state)
    (workspace / "solver.py").write_text(
        "import json, math, pathlib, sys\n"
        "data = json.loads(pathlib.Path(sys.argv[1]).read_text())\n"
        "n = data['N']\n"
        "p = next(v for v in range(2, math.isqrt(n) + 1) "
        "if n % v == 0)\n"
        "q = n // p\n"
        "d = pow(data['e'], -1, (p - 1) * (q - 1))\n"
        "plain = bytes(pow(v, d, n) for v in data['ciphertexts'])\n"
        "sys.stdout.buffer.write(plain)\n",
        encoding="utf-8",
    )
    (workspace / "original.json").write_bytes(CRYPTO_ORIGINAL)
    payloads = {
        "solver.py": (workspace / "solver.py").read_bytes(),
        "original.json": (workspace / "original.json").read_bytes(),
    }
    with tempfile.TemporaryDirectory(
        prefix="ctfos-release-operator-crypto-"
    ) as operator_temporary:
        operator_root = Path(operator_temporary)
        variant_path = operator_root / "variant.json"
        expected_path = operator_root / "variant.out"
        variant_path.write_bytes(CRYPTO_VARIANT)
        expected_path.write_bytes(CRYPTO_VARIANT_OUTPUT)
        _state, preissue = engine.preissue_managed_crypto_oracle(
            identity,
            variant_parameters_path=variant_path,
            variant_expected_output_path=expected_path,
            mutation_id="release-smoke-rsa-parameter-variant",
        )
    (workspace / "solver.py").unlink()
    (workspace / "original.json").unlink()
    _add_candidate(
        engine,
        identity,
        candidate_id=f"C-crypto-docker-{runtime}",
        value=CRYPTO_CANDIDATE,
    )

    committed, experiment = _execute_managed_builder_action(
        engine,
        identity,
        action={
            "kind": "prove_crypto_metamorphic",
            "description": "run the managed 3+3 metamorphic oracle",
            "candidate_id": f"C-crypto-docker-{runtime}",
            "solver_artifact_path": "solver.py",
            "original_parameters_artifact_path": "original.json",
            "oracle_preissue_id": preissue["preissue_id"],
            "runtime": runtime,
        },
        payloads=payloads,
    )
    committed_revision = committed.revision
    experiment_id = experiment.id
    final = engine.store.load(identity, recover=False)
    final.validate()
    verified_artifacts = engine.store.verify_artifacts(identity)
    if (
        final.revision != committed_revision
        or set(verified_artifacts)
        != {artifact.id for artifact in final.artifacts}
    ):
        raise AssertionError(
            "Crypto StateStore reload or physical artifact validation failed"
        )
    experiment = next(
        item for item in final.experiments if item.id == experiment_id
    )
    candidate = next(
        item
        for item in final.candidates
        if item.id == f"C-crypto-docker-{runtime}"
    )
    binding = candidate.extra.get("crypto_metamorphic_proof")
    challenge_root = engine.store.challenge_paths(identity).root
    runs, successful_attempts = _validated_crypto_execution(
        final,
        candidate,
        binding,
        challenge_root=challenge_root,
        image_digest=image_digest,
        runtime=runtime,
    )
    preissue_state = final.extra[MANAGED_ORACLE_PREISSUE_STATE_KEY][
        preissue["preissue_id"]
    ]
    if (
        not isinstance(binding, dict)
        or binding.get("passed") is not True
        or binding.get("oracle_authority")
        != MANAGED_ORACLE_PREISSUE_PROTOCOL
        or experiment.result.get("passed") is not True
        or candidate.status is not CandidateStatus.READY_TO_SUBMIT
        or len(runs) != 6
        or preissue_state.get("status") != "consumed"
        or not preissue_state.get("consumed_by_builder_run_id")
        or not preissue_state.get("consumed_by_experiment_id")
        or final.submissions
    ):
        raise AssertionError(
            "Crypto ChallengeEngine Docker hot path did not prove 3+3"
        )
    return {
        "candidate_status": candidate.status.value,
        "network": "none",
        "one_shot_consumed": True,
        "oracle_authority": MANAGED_ORACLE_PREISSUE_PROTOCOL,
        "oracle_preissue_status": preissue_state["status"],
        "runtime": runtime,
        "runs": len(runs),
        "successful_attempts": successful_attempts,
        "submissions": len(final.submissions),
    }


def _misc(root: Path, image_digest: str) -> dict[str, object]:
    engine = _engine(root, image_digest)
    identity = ChallengeIdentity(
        "release-smoke",
        "misc",
        "transform-hotpath",
    )
    incoming = engine.challenge_input(identity)
    incoming.mkdir(parents=True)
    (incoming / "challenge.bin").write_bytes(MISC_SOURCE)
    state = engine.add_challenge(
        identity,
        prompt="release smoke only",
        state_schema_version=STATE_SCHEMA_VERSION,
    )
    workspace = engine._workspace(state)
    (workspace / "transform.py").write_text(
        "import pathlib, sys\n"
        f"expected = {MISC_SOURCE!r}\n"
        "if pathlib.Path(sys.argv[1]).read_bytes() != expected:\n"
        "    raise SystemExit(41)\n"
        f"sys.stdout.write({MISC_CANDIDATE!r})\n",
        encoding="utf-8",
    )
    verifier_bytes = (
        "import pathlib, sys\n"
        f"candidate = {MISC_CANDIDATE.encode('utf-8')!r}\n"
        f"source = {MISC_SOURCE!r}\n"
        "valid = (pathlib.Path(sys.argv[1]).read_bytes() == candidate "
        "and pathlib.Path(sys.argv[2]).read_bytes() == source)\n"
        "raise SystemExit(0 if valid else 42)\n",
    )
    verifier_bytes = "".join(verifier_bytes).encode("utf-8")
    dag_spec = (
        json.dumps(
            {
                "schema_version": 1,
                "sources": [
                    {
                        "id": "original",
                        "locator": "challenge.bin",
                    }
                ],
                "steps": [
                    {
                        "id": "extract",
                        "parents": ["original"],
                        "tool_locator": "transform.py",
                    }
                ],
                "terminal_step_id": "extract",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    payloads = {
        "misc-spec.json": dag_spec,
        "transform.py": (workspace / "transform.py").read_bytes(),
    }
    with tempfile.TemporaryDirectory(
        prefix="ctfos-release-operator-misc-"
    ) as operator_temporary:
        verifier_path = Path(operator_temporary) / "verifier.py"
        verifier_path.write_bytes(verifier_bytes)
        _state, preissue = engine.preissue_managed_misc_oracle(
            identity,
            verifier_path=verifier_path,
            verifier_id="original-condition",
            oracle_id="release-smoke-oracle-v1",
        )
    (workspace / "transform.py").unlink()
    _add_candidate(
        engine,
        identity,
        candidate_id="C-misc-docker",
        value=MISC_CANDIDATE,
    )

    committed, experiment = _execute_managed_builder_action(
        engine,
        identity,
        action={
            "kind": "evaluate_misc_transform",
            "description": "run the managed DAG and hidden original oracle",
            "candidate_id": "C-misc-docker",
            "spec_artifact_path": "misc-spec.json",
            "oracle_preissue_id": preissue["preissue_id"],
        },
        payloads=payloads,
        extra_write_locators=("transform.py",),
    )
    committed_revision = committed.revision
    experiment_id = experiment.id
    final = engine.store.load(identity, recover=False)
    final.validate()
    verified_artifacts = engine.store.verify_artifacts(identity)
    if (
        final.revision != committed_revision
        or set(verified_artifacts)
        != {artifact.id for artifact in final.artifacts}
    ):
        raise AssertionError(
            "Misc StateStore reload or physical artifact validation failed"
        )
    experiment = next(
        item for item in final.experiments if item.id == experiment_id
    )
    candidate = next(
        item
        for item in final.candidates
        if item.id == "C-misc-docker"
    )
    binding = candidate.extra.get("misc_transform_evidence")
    run_ids = (
        binding.get("run_ids")
        if isinstance(binding, dict)
        else None
    )
    evaluation_id = (
        binding.get("misc_evaluation_id")
        if isinstance(binding, dict)
        else None
    )
    challenge_root = engine.store.challenge_paths(identity).root
    physical_runs, physical_counts = _validated_misc_execution(
        final,
        candidate,
        binding,
        challenge_root=challenge_root,
        image_digest=image_digest,
    )
    control_run_ids = (
        binding.get("oracle_control_run_ids")
        if isinstance(binding, dict)
        else None
    )
    preissue_state = final.extra[MANAGED_ORACLE_PREISSUE_STATE_KEY][
        preissue["preissue_id"]
    ]
    phases = [
        item.extra.get("phase")
        for item in physical_runs
    ]
    checks = {
        "binding": isinstance(binding, dict),
        "binding_passed": (
            isinstance(binding, dict)
            and binding.get("passed") is True
        ),
        "managed_authority": (
            isinstance(binding, dict)
            and binding.get("oracle_authority")
            == MANAGED_ORACLE_PREISSUE_PROTOCOL
        ),
        "negative_control": (
            isinstance(binding, dict)
            and binding.get("oracle_control_status") == "passed"
            and binding.get("oracle_negative_control_passed") is True
        ),
        "one_control_run": (
            isinstance(control_run_ids, list)
            and len(control_run_ids) == 1
        ),
        "experiment_passed": experiment.result.get("passed") is True,
        "candidate_only": (
            candidate.status is CandidateStatus.OBSERVED_CANDIDATE
            and not candidate.proof_run_ids
        ),
        "logical_runs": (
            isinstance(run_ids, list)
            and len(run_ids) == 4
        ),
        "physical_runs": len(physical_runs) == 5,
        "transform_runs": physical_counts["transform"] == 1,
        "control_runs": physical_counts["oracle-control"] == 1,
        "reverse_runs": physical_counts["reverse"] == 3,
        "preissue_consumed": (
            preissue_state.get("status") == "consumed"
            and bool(preissue_state.get("consumed_by_builder_run_id"))
            and bool(preissue_state.get("consumed_by_experiment_id"))
        ),
        "no_submissions": not final.submissions,
    }
    if not all(checks.values()):
        raise AssertionError(
            "Misc ChallengeEngine Docker hot path did not prove DAG+3: "
            + json.dumps(
                {
                    "checks": checks,
                    "logical_run_ids": run_ids,
                    "physical_phases": phases,
                },
                sort_keys=True,
            )
        )
    return {
        "candidate_only": True,
        "candidate_status": candidate.status.value,
        "network": "none",
        "one_shot_consumed": True,
        "oracle_authority": MANAGED_ORACLE_PREISSUE_PROTOCOL,
        "oracle_control_runs": len(control_run_ids),
        "oracle_preissue_status": preissue_state["status"],
        "runs": len(physical_runs),
        "submissions": len(final.submissions),
        "transform_evidence_passed": binding["passed"],
        "transform_runs": physical_counts["transform"],
        "verification_runs": physical_counts["reverse"],
    }


def main() -> int:
    image_digest = validate_image_digest(_parse_args().image_digest)
    readiness = inspect_pinned_capabilities(image_digest)
    if readiness.get("ok") is not True:
        raise AssertionError(
            "pinned image readiness failed: "
            + json.dumps(readiness, sort_keys=True)
        )
    with tempfile.TemporaryDirectory(
        prefix="ctfos-crypto-misc-docker-"
    ) as temporary:
        root = Path(temporary)
        crypto_python = _crypto(
            root / "crypto-python",
            image_digest,
            runtime="python",
        )
        crypto_sage = _crypto(
            root / "crypto-sage",
            image_digest,
            runtime="sage",
        )
        misc = _misc(root / "misc", image_digest)
    print(
        json.dumps(
            {
                "crypto": {
                    "python": crypto_python,
                    "sage": crypto_sage,
                },
                "image_digest": image_digest,
                "misc": misc,
                "ok": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
