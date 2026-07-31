"""Public candidate-free Rev accepted-input execution hot path."""

from __future__ import annotations

import copy
import hashlib
import json
import secrets
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Mapping

from ctf_os.adapters import get_adapter
from ctf_os.director.resources import tool_profile
from ctf_os.engine.rev_acceptance import (
    REV_ACCEPTANCE_MAX_EVIDENCE_BYTES,
    REV_ACCEPTANCE_MAX_INPUT_BYTES,
    REV_ACCEPTANCE_MAX_SPEC_BYTES,
    REV_ACCEPTANCE_MAX_STREAM_BYTES,
    REV_ACCEPTANCE_PROTOCOL,
    RevAcceptanceContractError,
    RevAcceptanceOperatorSpec,
    build_rev_acceptance_plan,
    canonical_json_bytes,
    evaluate_rev_acceptance,
    rev_acceptance_plan_sha256,
    sha256,
)
from ctf_os.engine.rev_acceptance_state import (
    REV_ACCEPTANCE_ENGINE_COMMAND,
    REV_ACCEPTANCE_STATE_EXECUTOR,
    REV_ACCEPTANCE_STATE_RESULT_KEY,
    REV_ACCEPTANCE_STATE_SCHEMA_VERSION,
    validate_rev_acceptance_state_graph,
)
from ctf_os.models import (
    ArtifactReference,
    ChallengeIdentity,
    ChallengeState,
    ChallengeStatus,
    ExecutionReceipt,
    Experiment,
    ExperimentKind,
    ExperimentStatus,
    Fact,
    FactKind,
    ProgressMarker,
    Provenance,
    ReceiptOutcome,
    RunOrigin,
    RunReference,
    RunStatus,
    utc_now,
)
from ctf_os.sandbox import CommandSpec, NetworkPolicy, ProofInput
from ctf_os.sandbox.files import (
    SafeFileError,
    copy_bounded_regular,
    ensure_private_directory,
    read_bounded_regular,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.stages.ingest import inventory_challenge
from ctf_os.store import ChallengeLock, LockTimeout
from ctf_os.store.atomic import (
    StrictJSONError,
    atomic_write_bytes,
    strict_json_loads,
)

if TYPE_CHECKING:
    from ctf_os.engine.challenge import ChallengeEngine


REV_ACCEPTANCE_HOTPATH_MAX_TIMEOUT_SECONDS = 3600


class RevAcceptanceHotPathError(RuntimeError):
    """One fail-closed accepted-input execution boundary."""


@dataclass(frozen=True, slots=True)
class _Snapshot:
    artifact_id: str
    path: str
    sha256: str
    size_bytes: int
    source_locator: str

    def binding(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "source_locator": self.source_locator,
        }


@dataclass(frozen=True, slots=True)
class _RunRecord:
    run: RunReference
    receipt: ExecutionReceipt
    artifacts: tuple[ArtifactReference, ArtifactReference]
    record: dict[str, object]


def _new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(16)}"


def _file_binding(
    root: Path,
    path: Path,
    *,
    maximum_bytes: int,
    source_size_admission: Callable[[int], None],
) -> tuple[str, int]:
    relative = path.relative_to(root).as_posix()
    with tempfile.TemporaryDirectory(
        prefix=".ctfos-rev-file-binding-",
        dir=root,
    ) as temporary:
        immutable = copy_bounded_regular(
            root,
            relative,
            Path(temporary) / "bound.bin",
            maximum_bytes=maximum_bytes,
            source_size_admission=source_size_admission,
            mode=0o400,
        )
    return immutable.sha256, immutable.size_bytes


def _artifact_extra(
    *,
    experiment_id: str,
    kind: str,
    **values: object,
) -> dict[str, object]:
    return {
        "experiment_id": experiment_id,
        "kind": kind,
        "protocol": REV_ACCEPTANCE_PROTOCOL,
        "rev_acceptance_state": True,
        **values,
    }


def _snapshot_workspace(
    engine: ChallengeEngine,
    state: ChallengeState,
    client: object,
    *,
    locator: str,
    destination: Path,
    artifact_id: str,
    maximum_bytes: int,
) -> _Snapshot:
    try:
        immutable = engine._snapshot_workspace_file(
            state,
            client,
            locator,
            destination,
        )
    except Exception as error:
        raise RevAcceptanceHotPathError(
            "rev_acceptance_workspace_snapshot_failed"
        ) from error
    if immutable.size_bytes > maximum_bytes:
        raise RevAcceptanceHotPathError(
            "rev_acceptance_workspace_snapshot_too_large"
        )
    return _Snapshot(
        artifact_id=artifact_id,
        path=immutable.path.relative_to(
            engine.store.challenge_paths(state.identity).root
        ).as_posix(),
        sha256=immutable.sha256,
        size_bytes=immutable.size_bytes,
        source_locator=locator,
    )


def _require_source_current(
    engine: ChallengeEngine,
    state: ChallengeState,
    *,
    source_locator: str,
    source_sha256: str,
    source_size_bytes: int,
    manifest_sha256: str,
) -> None:
    try:
        inventory = inventory_challenge(engine.challenge_input(state.identity))
    except (OSError, ValueError) as error:
        raise RevAcceptanceHotPathError(
            "rev_acceptance_source_inventory_failed"
        ) from error
    source = next(
        (item for item in inventory.files if item.path == source_locator),
        None,
    )
    if (
        inventory.manifest_sha256 != manifest_sha256
        or source is None
        or source.sha256 != source_sha256
        or source.size != source_size_bytes
        or state.metadata.get("source_manifest_sha256")
        != manifest_sha256
        or state.metadata.get("adapter_primary_source") != source_locator
    ):
        raise RevAcceptanceHotPathError(
            "rev_acceptance_source_binding_changed"
        )


def _complete_transport(result: object) -> bool:
    return (
        result is not None
        and result.timed_out is False
        and result.exit_code is not None
        and type(result.exit_code) is int
        and 0 <= result.exit_code <= 255
        and result.stdout_capture_complete is True
        and result.stderr_capture_complete is True
        and result.stdout_truncation_known is True
        and result.stderr_truncation_known is True
        and result.stdout_truncated is False
        and result.stderr_truncated is False
        and result.stdout_error is None
        and result.stderr_error is None
        and result.orchestration_error is None
        and result.stream_capture_error is None
    )


def execute_rev_acceptance_hotpath(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    operator_spec_locator: str,
    timeout_seconds: int = 300,
    _session_owned: bool = False,
) -> tuple[ChallengeState, dict[str, object]]:
    """Execute the original binary in three clean positives and controls."""

    if (
        type(operator_spec_locator) is not str
        or not operator_spec_locator
        or type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= REV_ACCEPTANCE_HOTPATH_MAX_TIMEOUT_SECONDS
    ):
        raise RevAcceptanceHotPathError(
            "rev_acceptance_request_invalid"
        )
    paths = engine.store.challenge_paths(identity)
    lock: ChallengeLock | None = None
    pending_artifacts: list[ArtifactReference] = []
    pending_run_ids: list[str] = []
    committed_state = False
    if not _session_owned:
        try:
            lock = ChallengeLock(
                paths.runtime / "session.lock",
                timeout=0,
            ).acquire()
        except LockTimeout as error:
            raise RevAcceptanceHotPathError(
                "rev_acceptance_session_busy"
            ) from error

    try:
        if not _session_owned:
            engine._recover_session_boundary(identity)
        engine._enforce_storage_admission(identity)
        state = engine.refresh_ingest(identity)
        engine._remaining_budget_seconds(state)
        if (
            state.schema_version < STATE_SCHEMA_VERSION
            or get_adapter(state.category).name != "reversing"
            or state.status
            in {
                ChallengeStatus.NEW,
                ChallengeStatus.PAUSED,
                ChallengeStatus.SOLVED,
                ChallengeStatus.ABANDONED,
            }
            or engine.config.runtime.image_digest is None
        ):
            raise RevAcceptanceHotPathError(
                "rev_acceptance_preflight_rejected"
            )
        before_candidate_ids = tuple(item.id for item in state.candidates)
        before_submission_ids = tuple(item.id for item in state.submissions)
        before_status = state.status
        base_revision = state.revision
        configuration_epoch = state.configuration_epoch

        try:
            binding, inventory_experiment, challenge_root = (
                engine._resolve_rev_stdin_inventory_binding(
                    state,
                    allowed_run_origins=frozenset(
                        {
                            RunOrigin.MANAGED_TOOL,
                            RunOrigin.OPERATOR_TOOL,
                        }
                    ),
                )
            )
        except Exception as error:
            raise RevAcceptanceHotPathError(
                "rev_acceptance_inventory_anchor_missing"
            ) from error
        source_locator = binding.source_binding["path"]
        source_sha256 = binding.source_binding["sha256"]
        source_size_bytes = binding.source_binding["size_bytes"]
        manifest_sha256 = binding.source_binding["manifest_sha256"]
        if (
            type(source_locator) is not str
            or type(source_sha256) is not str
            or type(source_size_bytes) is not int
            or type(manifest_sha256) is not str
        ):
            raise RevAcceptanceHotPathError(
                "rev_acceptance_source_binding_invalid"
            )
        _require_source_current(
            engine,
            state,
            source_locator=source_locator,
            source_sha256=source_sha256,
            source_size_bytes=source_size_bytes,
            manifest_sha256=manifest_sha256,
        )
        inventory_result = inventory_experiment.result
        if not isinstance(inventory_result, Mapping):
            raise RevAcceptanceHotPathError(
                "rev_acceptance_inventory_result_invalid"
            )
        inventory_receipt_id = inventory_result.get("receipt_id")
        if type(inventory_receipt_id) is not str:
            raise RevAcceptanceHotPathError(
                "rev_acceptance_inventory_receipt_missing"
            )

        experiment_id = _new_id("E-rev-accept")
        artifact_root = ensure_private_directory(
            paths.artifacts / "rev-acceptance" / experiment_id
        )
        client = engine.sandbox(
            state,
            challenge_dir_override=challenge_root,
            network_policy_override=NetworkPolicy.deny_all(),
        )
        spec_artifact_id = _new_id("A-rev-spec")
        spec_artifact_path = (
            artifact_root / "operator-spec.json"
        ).relative_to(paths.root).as_posix()
        pending_artifacts.append(
            ArtifactReference(
                id=spec_artifact_id,
                path=spec_artifact_path,
                sha256="0" * 64,
            )
        )
        spec_snapshot = _snapshot_workspace(
            engine,
            state,
            client,
            locator=operator_spec_locator,
            destination=artifact_root / "operator-spec.json",
            artifact_id=spec_artifact_id,
            maximum_bytes=REV_ACCEPTANCE_MAX_SPEC_BYTES,
        )
        try:
            spec_payload = read_bounded_regular(
                paths.root,
                spec_snapshot.path,
                maximum_bytes=REV_ACCEPTANCE_MAX_SPEC_BYTES,
                expected_sha256=spec_snapshot.sha256,
                expected_size=spec_snapshot.size_bytes,
            )
            spec = RevAcceptanceOperatorSpec.from_mapping(
                strict_json_loads(
                    spec_payload,
                    max_bytes=REV_ACCEPTANCE_MAX_SPEC_BYTES,
                )
            )
        except (
            OSError,
            SafeFileError,
            StrictJSONError,
            RevAcceptanceContractError,
            TypeError,
            ValueError,
        ) as error:
            raise RevAcceptanceHotPathError(
                "rev_acceptance_operator_spec_invalid"
            ) from error
        if (
            spec_payload != canonical_json_bytes(spec.to_dict())
            or spec.source_locator != source_locator
            or spec.accepted_input_locator == operator_spec_locator
        ):
            raise RevAcceptanceHotPathError(
                "rev_acceptance_operator_spec_binding_invalid"
            )

        input_artifact_id = _new_id("A-rev-input")
        input_artifact_path = (
            artifact_root / "accepted-input.bin"
        ).relative_to(paths.root).as_posix()
        pending_artifacts.append(
            ArtifactReference(
                id=input_artifact_id,
                path=input_artifact_path,
                sha256="0" * 64,
            )
        )
        input_snapshot = _snapshot_workspace(
            engine,
            state,
            client,
            locator=spec.accepted_input_locator,
            destination=artifact_root / "accepted-input.bin",
            artifact_id=input_artifact_id,
            maximum_bytes=REV_ACCEPTANCE_MAX_INPUT_BYTES,
        )
        try:
            accepted_input = read_bounded_regular(
                paths.root,
                input_snapshot.path,
                maximum_bytes=REV_ACCEPTANCE_MAX_INPUT_BYTES,
                expected_sha256=input_snapshot.sha256,
                expected_size=input_snapshot.size_bytes,
            )
            plan = build_rev_acceptance_plan(accepted_input)
        except (
            OSError,
            SafeFileError,
            RevAcceptanceContractError,
            TypeError,
            ValueError,
        ) as error:
            raise RevAcceptanceHotPathError(
                "rev_acceptance_input_invalid"
            ) from error

        spec_artifact = ArtifactReference(
            id=spec_snapshot.artifact_id,
            path=spec_snapshot.path,
            sha256=spec_snapshot.sha256,
            source_run_id=None,
            size=spec_snapshot.size_bytes,
            extra=_artifact_extra(
                experiment_id=experiment_id,
                kind="rev_acceptance_operator_spec",
                source_locator=operator_spec_locator,
            ),
        )
        input_artifact = ArtifactReference(
            id=input_snapshot.artifact_id,
            path=input_snapshot.path,
            sha256=input_snapshot.sha256,
            source_run_id=None,
            size=input_snapshot.size_bytes,
            extra=_artifact_extra(
                experiment_id=experiment_id,
                kind="rev_acceptance_input",
                source_locator=spec.accepted_input_locator,
            ),
        )
        argv = engine._rev_stdin_runner_argv(binding)
        command_timeout = engine._budget_command_timeout(
            state,
            timeout_seconds,
        )
        request_resources = tool_profile("standard", network=False)
        run_records: list[_RunRecord] = []
        observations: list[dict[str, object]] = []
        all_artifacts: list[ArtifactReference] = [
            spec_artifact,
            input_artifact,
        ]
        workspace = engine._workspace(state)
        with tempfile.TemporaryDirectory(
            prefix=".ctfos-rev-accept-inputs-",
            dir=workspace,
        ) as staging_name:
            staging = Path(staging_name)
            for planned in plan:
                payload_path = staging / (
                    f"attempt-{planned.ordinal:02d}.bin"
                )
                engine._enforce_storage_admission(
                    identity,
                    requested_bytes=len(planned.payload),
                )
                atomic_write_bytes(payload_path, planned.payload, mode=0o400)
                proof_input = ProofInput(
                    source_locator=payload_path.relative_to(
                        workspace
                    ).as_posix(),
                    destination_locator="oracle/accepted-input.bin",
                    sha256=planned.input_sha256,
                    size_bytes=len(planned.payload),
                )
                run_id = _new_id("R-rev-accept")
                pending_run_ids.append(run_id)
                receipt_id = _new_id("RCPT-rev-accept")
                request_payload = {
                    "argv": list(argv),
                    "configuration_epoch": configuration_epoch,
                    "experiment_id": experiment_id,
                    "image_digest": engine.config.runtime.image_digest,
                    "input_sha256": planned.input_sha256,
                    "input_size_bytes": len(planned.payload),
                    "kind": "rev_acceptance_oracle",
                    "mutation_id": planned.mutation_id,
                    "network": "none",
                    "ordinal": planned.ordinal,
                    "phase": planned.phase,
                    "protocol": REV_ACCEPTANCE_PROTOCOL,
                    "resource_request": request_resources.as_dict(),
                    "source_manifest_sha256": manifest_sha256,
                    "source_sha256": source_sha256,
                }
                run_paths = engine.store.create_run(
                    identity,
                    run_id=run_id,
                    request=request_payload,
                    base_revision=base_revision,
                )
                lease = engine.lease_broker.acquire(
                    request_resources,
                    timeout=engine._budget_wait_timeout(
                        state,
                        engine.config.resources.lease_wait_timeout_s,
                    ),
                    owner=(
                        f"{identity.key}:rev-accept:"
                        f"{experiment_id}:{planned.ordinal}"
                    ),
                )
                if lease is None:
                    raise RevAcceptanceHotPathError(
                        "rev_acceptance_resource_wait_timeout"
                    )
                started = time.monotonic()
                try:
                    result = client.run_clean_proof(
                        CommandSpec.create(
                            argv,
                            timeout_seconds=command_timeout,
                            network_target=None,
                            resource_request=request_resources,
                        ),
                        proof_inputs=(proof_input,),
                    )
                finally:
                    lease.release()
                wall_seconds = max(0.0, time.monotonic() - started)
                stream_artifacts: list[ArtifactReference] = []
                for stream_name, locator in (
                    ("stdout", result.stdout_path),
                    ("stderr", result.stderr_path),
                ):
                    artifact_id = _new_id(
                        f"A-rev-{stream_name}"
                    )
                    destination = (
                        artifact_root
                        / "streams"
                        / run_id
                        / f"{stream_name}.bin"
                    )
                    pending_artifacts.append(
                        ArtifactReference(
                            id=artifact_id,
                            path=destination.relative_to(
                                paths.root
                            ).as_posix(),
                            sha256="0" * 64,
                            source_run_id=run_id,
                        )
                    )
                    immutable = engine._snapshot_workspace_file(
                        state,
                        client,
                        locator.removeprefix("/work/"),
                        destination,
                    )
                    if immutable.size_bytes > REV_ACCEPTANCE_MAX_STREAM_BYTES:
                        raise RevAcceptanceHotPathError(
                            "rev_acceptance_stream_too_large"
                        )
                    stream_artifacts.append(
                        ArtifactReference(
                            id=artifact_id,
                            path=immutable.path.relative_to(
                                paths.root
                            ).as_posix(),
                            sha256=immutable.sha256,
                            source_run_id=run_id,
                            size=immutable.size_bytes,
                            extra=_artifact_extra(
                                experiment_id=experiment_id,
                                kind="rev_acceptance_stream",
                                ordinal=planned.ordinal,
                                stream=stream_name,
                            ),
                        )
                    )
                stdout_artifact, stderr_artifact = stream_artifacts
                observation = {
                    "capture_complete": _complete_transport(result),
                    "clean_workspace": True,
                    "exit_code": (
                        result.exit_code
                        if type(result.exit_code) is int
                        else 255
                    ),
                    "input_sha256": planned.input_sha256,
                    "input_size_bytes": len(planned.payload),
                    "mutation_id": planned.mutation_id,
                    "network": "none",
                    "ordinal": planned.ordinal,
                    "phase": planned.phase,
                    "receipt_id": receipt_id,
                    "run_id": run_id,
                    "stderr_artifact_id": stderr_artifact.id,
                    "stderr_sha256": stderr_artifact.sha256,
                    "stderr_size_bytes": stderr_artifact.size,
                    "stdout_artifact_id": stdout_artifact.id,
                    "stdout_sha256": stdout_artifact.sha256,
                    "stdout_size_bytes": stdout_artifact.size,
                    "timed_out": result.timed_out,
                }
                result_path = engine.store.write_run_result(
                    identity,
                    run_id,
                    {
                        "artifacts": [
                            item.to_dict()
                            for item in stream_artifacts
                        ],
                        "rev_acceptance_observation": observation,
                        "status": "completed",
                    },
                )
                validation_path = engine.store.write_run_validation(
                    identity,
                    run_id,
                    {
                        "rev_acceptance_observation": observation,
                        "status": (
                            "valid_transport"
                            if observation["capture_complete"]
                            else "invalid_transport"
                        ),
                    },
                )
                request_sha256, request_size = _file_binding(
                    paths.root,
                    run_paths.request,
                    maximum_bytes=REV_ACCEPTANCE_MAX_EVIDENCE_BYTES,
                    source_size_admission=lambda size: (
                        engine._enforce_storage_admission(
                            identity,
                            requested_bytes=size,
                        )
                    ),
                )
                result_sha256, result_size = _file_binding(
                    paths.root,
                    result_path,
                    maximum_bytes=REV_ACCEPTANCE_MAX_EVIDENCE_BYTES,
                    source_size_admission=lambda size: (
                        engine._enforce_storage_admission(
                            identity,
                            requested_bytes=size,
                        )
                    ),
                )
                validation_sha256, validation_size = _file_binding(
                    paths.root,
                    validation_path,
                    maximum_bytes=REV_ACCEPTANCE_MAX_EVIDENCE_BYTES,
                    source_size_admission=lambda size: (
                        engine._enforce_storage_admission(
                            identity,
                            requested_bytes=size,
                        )
                    ),
                )
                record = {
                    "observation": observation,
                    "request_path": run_paths.request.relative_to(
                        paths.root
                    ).as_posix(),
                    "request_sha256": request_sha256,
                    "request_size_bytes": request_size,
                    "result_path": result_path.relative_to(
                        paths.root
                    ).as_posix(),
                    "result_sha256": result_sha256,
                    "result_size_bytes": result_size,
                    "validation_path": validation_path.relative_to(
                        paths.root
                    ).as_posix(),
                    "validation_sha256": validation_sha256,
                    "validation_size_bytes": validation_size,
                }
                marker = {
                    "mutation_id": planned.mutation_id,
                    "ordinal": planned.ordinal,
                    "protocol": REV_ACCEPTANCE_PROTOCOL,
                }
                run = RunReference(
                    id=run_id,
                    base_revision=base_revision,
                    status=RunStatus.COMPLETED,
                    request_path=record["request_path"],
                    result_path=record["result_path"],
                    validation_path=record["validation_path"],
                    role="rev_acceptance_oracle",
                    origin=(
                        RunOrigin.MANAGED_TOOL
                        if _session_owned
                        else RunOrigin.OPERATOR_TOOL
                    ),
                    configuration_epoch=configuration_epoch,
                    extra={
                        "experiment_id": experiment_id,
                        "request_sha256": request_sha256,
                        "request_size_bytes": request_size,
                        "result_sha256": result_sha256,
                        "result_size_bytes": result_size,
                        "rev_acceptance_state": marker,
                        "validation_sha256": validation_sha256,
                        "validation_size_bytes": validation_size,
                    },
                )
                receipt = ExecutionReceipt(
                    id=receipt_id,
                    experiment_id=experiment_id,
                    run_id=run_id,
                    outcome=ReceiptOutcome.SUCCEEDED,
                    exit_code=observation["exit_code"],
                    wall_seconds=wall_seconds,
                    stdout_artifact_id=stdout_artifact.id,
                    stderr_artifact_id=stderr_artifact.id,
                    stdout_bytes=stdout_artifact.size or 0,
                    stderr_bytes=stderr_artifact.size or 0,
                    stdout_lines=0,
                    stderr_lines=0,
                    preview=(
                        "Rev original-binary oracle attempt completed"
                    ),
                    extra={"rev_acceptance_state": marker},
                )
                run_records.append(
                    _RunRecord(
                        run=run,
                        receipt=receipt,
                        artifacts=(
                            stdout_artifact,
                            stderr_artifact,
                        ),
                        record=record,
                    )
                )
                observations.append(observation)
                all_artifacts.extend(stream_artifacts)

        evaluation = evaluate_rev_acceptance(
            spec=spec,
            plan=plan,
            observations=observations,
            source_manifest_sha256=manifest_sha256,
            source_sha256=source_sha256,
            source_size_bytes=source_size_bytes,
            image_digest=engine.config.runtime.image_digest,
        )
        evaluation_payload = canonical_json_bytes(evaluation)
        evaluation_sha256 = sha256(evaluation_payload)
        evaluation_artifact_id = _new_id("A-rev-evaluation")
        evaluation_path = artifact_root / "evaluation.json"
        pending_artifacts.append(
            ArtifactReference(
                id=evaluation_artifact_id,
                path=evaluation_path.relative_to(
                    paths.root
                ).as_posix(),
                sha256="0" * 64,
                source_run_id=run_records[-1].run.id,
            )
        )
        engine._enforce_storage_admission(
            identity,
            requested_bytes=len(evaluation_payload),
        )
        atomic_write_bytes(evaluation_path, evaluation_payload, mode=0o400)
        final_run_id = run_records[-1].run.id
        evaluation_artifact = ArtifactReference(
            id=evaluation_artifact_id,
            path=evaluation_path.relative_to(paths.root).as_posix(),
            sha256=evaluation_sha256,
            source_run_id=final_run_id,
            size=len(evaluation_payload),
            extra=_artifact_extra(
                experiment_id=experiment_id,
                kind="rev_acceptance_evaluation",
                evaluation_sha256=evaluation_sha256,
            ),
        )
        all_artifacts.append(evaluation_artifact)
        fact_id = _new_id("F-rev-accept") if evaluation["passed"] else None
        progress_id = (
            _new_id("P-rev-accept") if evaluation["passed"] else None
        )
        source_binding = {
            "inventory_experiment_id": inventory_experiment.id,
            "inventory_receipt_id": inventory_receipt_id,
            "inventory_run_id": binding.inventory_run_id,
            "inventory_stdout_artifact_id": (
                binding.inventory_stdout_artifact_id
            ),
            "locator": source_locator,
            "manifest_sha256": manifest_sha256,
            "sha256": source_sha256,
            "size_bytes": source_size_bytes,
        }
        plan_mapping = [item.to_dict() for item in plan]
        evidence = {
            "accepted_input_artifact": input_snapshot.binding(),
            "authorities": copy.deepcopy(evaluation["authorities"]),
            "base_revision": base_revision,
            "configuration_epoch": configuration_epoch,
            "evaluation": copy.deepcopy(evaluation),
            "evaluation_artifact_id": evaluation_artifact.id,
            "evaluation_sha256": evaluation_sha256,
            "experiment_id": experiment_id,
            "fact_id": fact_id,
            "image_digest": engine.config.runtime.image_digest,
            "operator_spec": spec.to_dict(),
            "operator_spec_artifact": spec_snapshot.binding(),
            "plan": plan_mapping,
            "plan_sha256": rev_acceptance_plan_sha256(plan),
            "progress_id": progress_id,
            "protocol": REV_ACCEPTANCE_PROTOCOL,
            "records": [copy.deepcopy(item.record) for item in run_records],
            "schema_version": REV_ACCEPTANCE_STATE_SCHEMA_VERSION,
            "source": source_binding,
        }
        evaluated_at = utc_now()
        experiment = Experiment(
            id=experiment_id,
            hypothesis_ids=[],
            command=REV_ACCEPTANCE_ENGINE_COMMAND,
            expected_observation=(
                "three exact accepted replays and three exact mutation "
                "rejections from the original binary"
            ),
            keep_if="the candidate-free 3+3 executable oracle passes",
            drop_if="any transport, hash, exit, or output binding differs",
            timeout_seconds=command_timeout,
            resource_class="standard",
            kind=ExperimentKind.PROBE,
            status=(
                ExperimentStatus.COMPLETED
                if evaluation["passed"]
                else ExperimentStatus.FAILED
            ),
            result={REV_ACCEPTANCE_STATE_RESULT_KEY: evidence},
            artifact_ids=[item.id for item in all_artifacts],
            evidence_fact_ids=[fact_id] if fact_id is not None else [],
            evidence_run_ids=[item.run.id for item in run_records],
            evidence_receipt_ids=[
                item.receipt.id for item in run_records
            ],
            evaluation_reason=(
                "rev_acceptance:passed"
                if evaluation["passed"]
                else (
                    "rev_acceptance:"
                    + ",".join(evaluation["reason_codes"])
                )[:512]
            ),
            evaluated_at=evaluated_at,
            extra={
                "engine_executor": REV_ACCEPTANCE_STATE_EXECUTOR,
                "rev_acceptance_state": {
                    "evaluation_sha256": evaluation_sha256,
                    "protocol": REV_ACCEPTANCE_PROTOCOL,
                },
            },
        )
        authority_marker = {
            "evaluation_sha256": evaluation_sha256,
            "protocol": REV_ACCEPTANCE_PROTOCOL,
            "rev_acceptance_state": True,
        }
        fact = (
            Fact(
                id=fact_id,
                statement=(
                    "Original Rev binary accepted the exact input in three "
                    "clean runs and rejected three fixed mutations"
                ),
                provenance=Provenance.EXECUTED,
                kind=FactKind.OBSERVATION,
                challenge_id=state.challenge_id,
                source_run_id=final_run_id,
                artifact_id=evaluation_artifact.id,
                locator=evaluation_artifact.path,
                extra=copy.deepcopy(authority_marker),
            )
            if fact_id is not None
            else None
        )
        progress = (
            ProgressMarker(
                id=progress_id,
                statement=(
                    "Rev original-binary accepted-input oracle passed 3+3"
                ),
                run_id=final_run_id,
                artifact_ids=[
                    evaluation_artifact.id,
                    input_artifact.id,
                ],
                extra=copy.deepcopy(authority_marker),
            )
            if progress_id is not None
            else None
        )

        def commit(current: ChallengeState) -> None:
            if (
                current.revision != base_revision
                or current.configuration_epoch != configuration_epoch
                or current.status is not before_status
                or tuple(item.id for item in current.candidates)
                != before_candidate_ids
                or tuple(item.id for item in current.submissions)
                != before_submission_ids
            ):
                raise RevAcceptanceHotPathError(
                    "rev_acceptance_state_changed_before_commit"
                )
            _require_source_current(
                engine,
                current,
                source_locator=source_locator,
                source_sha256=source_sha256,
                source_size_bytes=source_size_bytes,
                manifest_sha256=manifest_sha256,
            )
            for snapshot, maximum in (
                (spec_snapshot, REV_ACCEPTANCE_MAX_SPEC_BYTES),
                (input_snapshot, REV_ACCEPTANCE_MAX_INPUT_BYTES),
            ):
                read_bounded_regular(
                    paths.root,
                    snapshot.path,
                    maximum_bytes=maximum,
                    expected_sha256=snapshot.sha256,
                    expected_size=snapshot.size_bytes,
                )
            read_bounded_regular(
                paths.root,
                evaluation_artifact.path,
                maximum_bytes=REV_ACCEPTANCE_MAX_EVIDENCE_BYTES,
                expected_sha256=evaluation_artifact.sha256,
                expected_size=evaluation_artifact.size,
            )
            current.artifacts.extend(all_artifacts)
            current.runs.extend(item.run for item in run_records)
            current.receipts.extend(
                item.receipt for item in run_records
            )
            current.experiments.append(experiment)
            if fact is not None and progress is not None:
                current.facts.append(fact)
                current.progress_markers.append(progress)
            validate_rev_acceptance_state_graph(current)

        committed = engine.store.update(
            identity,
            commit,
            expected_revision=base_revision,
        )
        committed_state = True
        if (
            committed.status is not before_status
            or tuple(item.id for item in committed.candidates)
            != before_candidate_ids
            or tuple(item.id for item in committed.submissions)
            != before_submission_ids
        ):
            raise RevAcceptanceHotPathError(
                "rev_acceptance_authority_boundary_broken"
            )
        return committed, evaluation
    except BaseException as error:
        if not committed_state:
            try:
                engine._cleanup_uncommitted_artifacts(
                    identity,
                    pending_artifacts,
                    cause=error,
                )
            except BaseException as cleanup_error:
                error.add_note(
                    "Rev accepted-input artifact cleanup failed: "
                    f"{type(cleanup_error).__name__}"
                )
            try:
                # create_run uses the same exact fixed topology as the
                # existing six-attempt crash gate; its remover verifies
                # canonical absence, bounded IDs, file types, and emptiness.
                engine._cleanup_uncommitted_pwn_crash_runs(
                    identity,
                    pending_run_ids,
                    cause=error,
                )
            except BaseException as cleanup_error:
                error.add_note(
                    "Rev accepted-input run cleanup failed: "
                    f"{type(cleanup_error).__name__}"
                )
        raise
    finally:
        if lock is not None:
            lock.release()


__all__ = [
    "REV_ACCEPTANCE_HOTPATH_MAX_TIMEOUT_SECONDS",
    "RevAcceptanceHotPathError",
    "execute_rev_acceptance_hotpath",
]
