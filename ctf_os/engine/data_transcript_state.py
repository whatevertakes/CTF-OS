"""Persistence invariants for managed Crypto/Misc transcript attempts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping

from ctf_os.capabilities import REQUIRED_MANAGED_ATTESTATIONS
from ctf_os.codex.contracts import MANAGED_DATA_TRANSCRIPT_ACTION_KIND
from ctf_os.contracts.data_transcript_v1 import (
    DATA_TRANSCRIPT_V1_CONTRACT_FINGERPRINT,
)
from ctf_os.engine.data_transcript import (
    DATA_TRANSCRIPT_MAX_HISTORY,
    DATA_TRANSCRIPT_STATE_KEY,
)
from ctf_os.models import (
    ArtifactReference,
    ChallengeState,
    ExperimentStatus,
    RunOrigin,
    RunStatus,
)


_PROTOCOL = "ctfos.data_transcript.hotpath.v1"
_PREISSUE_KEY = "managed_oracle_preissues"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CLEAN_PREFIX = re.compile(r"^clean-[0-9a-f]{12}$")
_RUN_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,255}$")
_FAILURE_CODE = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
_PHASES = (
    ("positive", 1),
    ("positive", 2),
    ("positive", 3),
    ("control", 1),
    ("control", 2),
    ("control", 3),
)
_CAPTURE_KINDS = (
    "producer_stdout",
    "producer_stderr",
    "peer_stdout",
    "peer_stderr",
    "transcript",
    "reset_proof",
)
_BINDING_KEYS = {"artifact_id", "path", "sha256", "size_bytes"}
_RESERVED_REPLAY_KEYS = {
    "artifact_ids",
    "ordinal",
    "phase",
    "run_id",
    "sidecar_artifact_ids",
}
_PREISSUED_REPLAY_KEYS = {
    "artifact_ids",
    "ordinal",
    "phase",
    "request_artifact",
    "result_artifact_id",
    "run_id",
    "validation_artifact_id",
}
_TERMINAL_REPLAY_KEYS = {
    "artifact_ids",
    "ordinal",
    "phase",
    "request_artifact",
    "result_artifact",
    "run_id",
    "validation_artifact",
}
_COMMON_KEYS = {
    "attempt_id",
    "automatic_submission_authorized",
    "candidate_authorized",
    "configuration_epoch",
    "contract_fingerprint",
    "image_digest",
    "managed_builder_run_id",
    "managed_experiment_id",
    "oracle_preissue_id",
    "oracle_preissue_sha256",
    "protocol",
    "recipe_artifact_id",
    "recipe_sha256",
    "recipe_size_bytes",
    "reset_commitment_sha256",
    "replays",
    "schema_version",
    "source_manifest_sha256",
    "status",
    "terminal",
}
_FAILURE_KEYS = {
    "completed_at",
    "execution_error_type",
    "failure_code",
}
_PASSED_KEYS = {
    "completed_at",
    "evaluation_artifact_id",
    "evaluation_sha256",
    "proof_identities",
    "reason_code",
    "unique_clean_prefix_count",
    "unique_proof_identity_count",
    "unique_sandbox_run_id_count",
}


def _sha(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _canonical_sha(value: object) -> tuple[str, int]:
    payload = _canonical_bytes(value)
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _binding_valid(value: object) -> bool:
    return (
        type(value) is dict
        and set(value) == _BINDING_KEYS
        and type(value.get("artifact_id")) is str
        and bool(value["artifact_id"])
        and type(value.get("path")) is str
        and bool(value["path"])
        and _sha(value.get("sha256"))
        and type(value.get("size_bytes")) is int
        and value["size_bytes"] >= 1
    )


def _binding_matches(
    artifact: ArtifactReference | None,
    binding: dict[str, object],
    *,
    attempt_id: str,
    run_id: str,
    phase: str,
    ordinal: int,
    kind: str,
    expected_path: str,
) -> bool:
    return (
        artifact is not None
        and artifact.id == binding["artifact_id"]
        and artifact.path == binding["path"] == expected_path
        and artifact.sha256 == binding["sha256"]
        and artifact.size == binding["size_bytes"]
        and artifact.source_run_id == run_id
        and artifact.media_type == "application/json"
        and artifact.extra
        == {
            "attempt_id": attempt_id,
            "context_visibility": "engine_private",
            "kind": f"data_transcript_{kind}",
            "ordinal": ordinal,
            "phase": phase,
            "protocol": _PROTOCOL,
        }
    )


def _replay_shape(
    value: object,
) -> tuple[str, tuple[str, ...], set[str]] | None:
    if type(value) is not list or len(value) != 6:
        return None
    run_ids: list[str] = []
    all_artifact_ids: set[str] = set()
    sidecar_ids: list[str] = []
    shape: str | None = None
    for replay, expected in zip(value, _PHASES, strict=True):
        if type(replay) is not dict:
            return None
        keys = set(replay)
        current_shape = (
            "reserved"
            if keys == _RESERVED_REPLAY_KEYS
            else (
                "preissued"
                if keys == _PREISSUED_REPLAY_KEYS
                else (
                    "terminal"
                    if keys == _TERMINAL_REPLAY_KEYS
                    else None
                )
            )
        )
        if (
            current_shape is None
            or (shape is not None and current_shape != shape)
            or (replay.get("phase"), replay.get("ordinal")) != expected
            or type(replay.get("run_id")) is not str
            or _RUN_ID.fullmatch(replay["run_id"]) is None
            or type(replay.get("artifact_ids")) is not list
            or len(replay["artifact_ids"]) != 6
            or any(
                type(item) is not str or not item
                for item in replay["artifact_ids"]
            )
        ):
            return None
        if current_shape == "reserved":
            planned = replay.get("sidecar_artifact_ids")
            if (
                type(planned) is not dict
                or set(planned) != {"request", "result", "validation"}
                or any(
                    type(item) is not str or not item
                    for item in planned.values()
                )
            ):
                return None
            sidecar_ids.extend(planned.values())
        elif current_shape == "preissued":
            if (
                not _binding_valid(replay.get("request_artifact"))
                or type(replay.get("result_artifact_id")) is not str
                or not replay["result_artifact_id"]
                or type(replay.get("validation_artifact_id")) is not str
                or not replay["validation_artifact_id"]
            ):
                return None
            sidecar_ids.extend(
                (
                    replay["request_artifact"]["artifact_id"],
                    replay["result_artifact_id"],
                    replay["validation_artifact_id"],
                )
            )
        else:
            if (
                not _binding_valid(replay.get("request_artifact"))
                or not _binding_valid(replay.get("result_artifact"))
                or not _binding_valid(
                    replay.get("validation_artifact")
                )
            ):
                return None
            sidecar_ids.extend(
                (
                    replay["request_artifact"]["artifact_id"],
                    replay["result_artifact"]["artifact_id"],
                    replay["validation_artifact"]["artifact_id"],
                )
            )
        shape = current_shape
        run_ids.append(replay["run_id"])
        all_artifact_ids.update(replay["artifact_ids"])
    if (
        len(set(run_ids)) != 6
        or len(all_artifact_ids) != 36
        or len(set(sidecar_ids)) != 18
        or all_artifact_ids.intersection(sidecar_ids)
    ):
        return None
    return shape or "", tuple(run_ids), set(sidecar_ids)


def _proof_identities(
    value: object,
) -> tuple[list[dict[str, object]], bool]:
    if type(value) is not list or len(value) != 6:
        return [], False
    identities: list[dict[str, object]] = []
    tuples: list[tuple[str, str, str]] = []
    for identity in value:
        if (
            type(identity) is not dict
            or set(identity)
            != {
                "clean_prefix",
                "sandbox_run_id",
                "scope_fingerprint",
            }
            or type(identity.get("clean_prefix")) is not str
            or _CLEAN_PREFIX.fullmatch(identity["clean_prefix"]) is None
            or type(identity.get("sandbox_run_id")) is not str
            or _RUN_ID.fullmatch(identity["sandbox_run_id"]) is None
            or not _sha(identity.get("scope_fingerprint"))
        ):
            return [], False
        identities.append(identity)
        tuples.append(
            (
                identity["scope_fingerprint"],
                identity["sandbox_run_id"],
                identity["clean_prefix"],
            )
        )
    return (
        identities,
        len(set(tuples)) == 6
        and len({item[1] for item in tuples}) == 6
        and len({item[2] for item in tuples}) == 6,
    )


def _typed_gate_result(
    *,
    passed: bool,
    reason_codes: list[str],
    evaluation_sha256: str | None,
    evidence_artifact_ids: list[str],
    evidence_run_ids: list[str],
    execution_error_type: str | None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "action_kind": MANAGED_DATA_TRANSCRIPT_ACTION_KIND,
        "authority": "engine_deterministic_gate",
        "passed": passed,
        "reason_codes": reason_codes,
        "evaluation_sha256": evaluation_sha256,
        "evidence_artifact_ids": evidence_artifact_ids,
        "evidence_run_ids": evidence_run_ids,
        "execution_error_type": execution_error_type,
    }


def data_transcript_state_errors(
    state: ChallengeState,
) -> list[str]:
    """Return exact graph errors for every durable transcript reservation."""

    errors: list[str] = []
    history = state.extra.get(DATA_TRANSCRIPT_STATE_KEY)
    preissues = state.extra.get(_PREISSUE_KEY)
    consumed_transcripts = (
        [
            value
            for value in preissues.values()
            if isinstance(value, Mapping)
            and value.get("kind")
            in {"crypto_transcript", "misc_transcript"}
            and value.get("status") == "consumed"
        ]
        if type(preissues) is dict
        else []
    )
    if history is None:
        if consumed_transcripts:
            errors.append(
                "consumed transcript preissue lacks an attempt journal"
            )
        return errors
    if type(history) is not dict:
        return ["data transcript history is not a mapping"]
    if len(history) > DATA_TRANSCRIPT_MAX_HISTORY:
        errors.append("data transcript history exceeds its bounded limit")

    run_index = {item.id: item for item in state.runs}
    experiment_index = {item.id: item for item in state.experiments}
    artifact_index = {item.id: item for item in state.artifacts}
    journal_preissue_ids: list[str] = []
    journal_run_ids: set[str] = set()
    journal_artifact_ids: set[str] = set()
    for attempt_id, journal in history.items():
        label = f"data transcript journal {attempt_id}"
        if (
            type(attempt_id) is not str
            or not attempt_id
            or type(journal) is not dict
            or journal.get("attempt_id") != attempt_id
            or journal.get("protocol") != _PROTOCOL
            or journal.get("schema_version") != 1
            or journal.get("contract_fingerprint")
            != DATA_TRANSCRIPT_V1_CONTRACT_FINGERPRINT
            or journal.get("candidate_authorized") is not False
            or journal.get("automatic_submission_authorized") is not False
            or type(journal.get("configuration_epoch")) is not int
            or journal.get("configuration_epoch")
            != state.configuration_epoch
            or journal.get("source_manifest_sha256")
            != state.metadata.get("source_manifest_sha256")
            or not _IMAGE.fullmatch(str(journal.get("image_digest", "")))
            or not _sha(journal.get("oracle_preissue_sha256"))
            or not _sha(journal.get("recipe_sha256"))
            or not _sha(journal.get("reset_commitment_sha256"))
            or type(journal.get("recipe_size_bytes")) is not int
            or journal["recipe_size_bytes"] < 1
            or type(journal.get("recipe_artifact_id")) is not str
            or not journal["recipe_artifact_id"]
            or type(journal.get("managed_builder_run_id")) is not str
            or type(journal.get("managed_experiment_id")) is not str
            or type(journal.get("oracle_preissue_id")) is not str
        ):
            errors.append(f"{label} has an invalid common binding")
            continue
        status = journal.get("status")
        terminal = journal.get("terminal")
        if (
            status not in {"reserved", "preissued", "passed", "failed"}
            or terminal is not (status in {"passed", "failed"})
        ):
            errors.append(f"{label} has an invalid lifecycle state")
            continue
        replay_shape = _replay_shape(journal.get("replays"))
        if replay_shape is None:
            errors.append(f"{label} has an invalid replay reservation")
            continue
        shape, run_ids, sidecar_ids = replay_shape
        capture_id_set = {
            artifact_id
            for replay in journal["replays"]
            for artifact_id in replay["artifact_ids"]
        }
        evaluation_identity = (
            {journal["evaluation_artifact_id"]}
            if status == "passed"
            and type(journal.get("evaluation_artifact_id")) is str
            else set()
        )
        current_artifact_ids = (
            capture_id_set | sidecar_ids | evaluation_identity
        )
        if (
            evaluation_identity.intersection(
                capture_id_set | sidecar_ids
            )
            or journal_run_ids.intersection(run_ids)
            or journal_artifact_ids.intersection(
                current_artifact_ids
            )
        ):
            errors.append(f"{label} reuses another attempt identity")
            continue
        journal_run_ids.update(run_ids)
        journal_artifact_ids.update(current_artifact_ids)
        expected_keys = (
            _COMMON_KEYS
            if status == "reserved"
            else {*_COMMON_KEYS, "capability"}
            if status == "preissued"
            else {*_COMMON_KEYS, "capability", *_PASSED_KEYS}
            if status == "passed"
            else {*_COMMON_KEYS, *_FAILURE_KEYS}
            if shape == "reserved"
            else {*_COMMON_KEYS, "capability", *_FAILURE_KEYS}
        )
        if (
            set(journal) != expected_keys
            or (status == "reserved" and shape != "reserved")
            or (status == "preissued" and shape != "preissued")
            or (status == "passed" and shape != "terminal")
            or (
                status == "failed"
                and shape not in {"reserved", "terminal"}
            )
            or (
                shape != "reserved"
                and journal.get("capability")
                != REQUIRED_MANAGED_ATTESTATIONS[
                    "data_transcript_v1"
                ]
            )
            or (
                terminal is True
                and (
                    type(journal.get("completed_at")) is not str
                    or not journal["completed_at"]
                )
            )
            or (
                status == "failed"
                and (
                    type(journal.get("failure_code")) is not str
                    or _FAILURE_CODE.fullmatch(
                        journal["failure_code"]
                    )
                    is None
                    or type(journal.get("execution_error_type"))
                    is not str
                    or not journal["execution_error_type"]
                    or len(journal["execution_error_type"]) > 128
                )
            )
        ):
            errors.append(f"{label} has an invalid replay lifecycle")
            continue

        builder_id = journal["managed_builder_run_id"]
        experiment_id = journal["managed_experiment_id"]
        preissue_id = journal["oracle_preissue_id"]
        builder = run_index.get(builder_id)
        experiment = experiment_index.get(experiment_id)
        recipe = artifact_index.get(journal["recipe_artifact_id"])
        preissue = (
            preissues.get(preissue_id)
            if type(preissues) is dict
            else None
        )
        if (
            builder is None
            or builder.role != "builder"
            or builder.origin is not RunOrigin.MANAGED_MODEL
            or builder.status is not RunStatus.COMPLETED
            or experiment is None
            or experiment.source_run_id != builder_id
            or recipe is None
            or recipe.source_run_id != builder_id
            or recipe.sha256 != journal["recipe_sha256"]
            or recipe.size != journal["recipe_size_bytes"]
            or not isinstance(preissue, Mapping)
            or preissue.get("status") != "consumed"
            or preissue.get("kind")
            not in {"crypto_transcript", "misc_transcript"}
            or preissue.get("oracle_seal_sha256")
            != journal["oracle_preissue_sha256"]
            or preissue.get("reset_commitment_sha256")
            != journal["reset_commitment_sha256"]
            or preissue.get("consumed_by_builder_run_id") != builder_id
            or preissue.get("consumed_by_experiment_id")
            != experiment_id
        ):
            errors.append(f"{label} has a rebound authority binding")
            continue
        journal_preissue_ids.append(preissue_id)

        replays = journal["replays"]
        child_runs = [run_index.get(run_id) for run_id in run_ids]
        capture_ids = [
            artifact_id
            for replay in replays
            for artifact_id in replay["artifact_ids"]
        ]
        if shape == "reserved":
            if (
                any(item is not None for item in child_runs)
                or any(
                    artifact_id in artifact_index
                    for artifact_id in (*capture_ids, *sidecar_ids)
                )
            ):
                errors.append(
                    f"{label} reserved replay has durable children"
                )
            expected_attempt_artifact_ids: list[str] = []
            expected_evidence_run_ids: list[str] = []
            proof_identities: list[dict[str, object]] = []
        else:
            expected_attempt_artifact_ids = []
            expected_evidence_run_ids = list(run_ids)
            proof_identities, identities_valid = (
                _proof_identities(journal.get("proof_identities"))
                if status == "passed"
                else ([], True)
            )
            if status == "passed" and (
                not identities_valid
                or journal.get("unique_proof_identity_count") != 6
                or journal.get("unique_sandbox_run_id_count") != 6
                or journal.get("unique_clean_prefix_count") != 6
                or type(journal.get("reason_code")) is not str
                or not journal["reason_code"]
                or len(journal["reason_code"]) > 160
            ):
                errors.append(
                    f"{label} has invalid proof identity topology"
                )

            for position, (replay, run) in enumerate(
                zip(replays, child_runs, strict=True)
            ):
                run_id = replay["run_id"]
                phase = replay["phase"]
                ordinal = replay["ordinal"]
                request_binding = replay["request_artifact"]
                request_artifact = artifact_index.get(
                    request_binding["artifact_id"]
                )
                expected_attempt_artifact_ids.append(
                    request_binding["artifact_id"]
                )
                expected_run_binding: dict[str, object] = {
                    "attempt_id": attempt_id,
                    "ordinal": ordinal,
                    "phase": phase,
                    "protocol": _PROTOCOL,
                }
                expected_status = (
                    RunStatus.CREATED
                    if status == "preissued"
                    else (
                        RunStatus.COMPLETED
                        if status == "passed"
                        else RunStatus.FAILED
                    )
                )
                if status == "passed" and len(proof_identities) == 6:
                    expected_run_binding.update(
                        {
                            "proof_identity": proof_identities[position],
                            "terminal": True,
                        }
                    )
                elif status == "failed":
                    expected_run_binding.update(
                        {
                            "failure_code": journal["failure_code"],
                            "terminal": True,
                        }
                    )
                if (
                    run is None
                    or run.status is not expected_status
                    or run.role != "data_transcript"
                    or run.origin is not RunOrigin.MANAGED_TOOL
                    or run.configuration_epoch
                    != journal["configuration_epoch"]
                    or run.request_path != request_binding["path"]
                    or set(run.extra) != {"data_transcript"}
                    or run.extra.get("data_transcript")
                    != expected_run_binding
                    or not _binding_matches(
                        request_artifact,
                        request_binding,
                        attempt_id=attempt_id,
                        run_id=run_id,
                        phase=phase,
                        ordinal=ordinal,
                        kind="request",
                        expected_path=f"runs/{run_id}/request.json",
                    )
                ):
                    errors.append(
                        f"{label} child run {run_id} request is not exact"
                    )
                if status == "preissued":
                    if (
                        run is not None
                        and (
                            run.result_path is not None
                            or run.validation_path is not None
                        )
                    ) or replay["result_artifact_id"] in artifact_index or (
                        replay["validation_artifact_id"]
                        in artifact_index
                    ) or any(
                        artifact_id in artifact_index
                        for artifact_id in replay["artifact_ids"]
                    ):
                        errors.append(
                            f"{label} preissued run {run_id} is terminal"
                        )
                    continue

                result_binding = replay["result_artifact"]
                validation_binding = replay["validation_artifact"]
                result_artifact = artifact_index.get(
                    result_binding["artifact_id"]
                )
                validation_artifact = artifact_index.get(
                    validation_binding["artifact_id"]
                )
                expected_attempt_artifact_ids.extend(
                    (
                        result_binding["artifact_id"],
                        validation_binding["artifact_id"],
                    )
                )
                if (
                    run is None
                    or run.result_path != result_binding["path"]
                    or run.validation_path
                    != validation_binding["path"]
                    or not _binding_matches(
                        result_artifact,
                        result_binding,
                        attempt_id=attempt_id,
                        run_id=run_id,
                        phase=phase,
                        ordinal=ordinal,
                        kind="result",
                        expected_path=f"runs/{run_id}/result.json",
                    )
                    or not _binding_matches(
                        validation_artifact,
                        validation_binding,
                        attempt_id=attempt_id,
                        run_id=run_id,
                        phase=phase,
                        ordinal=ordinal,
                        kind="validation",
                        expected_path=f"runs/{run_id}/validation.json",
                    )
                ):
                    errors.append(
                        f"{label} child run {run_id} sidecars are not exact"
                    )

                if status == "passed":
                    capture_artifacts: list[ArtifactReference] = []
                    for artifact_id, kind in zip(
                        replay["artifact_ids"],
                        _CAPTURE_KINDS,
                        strict=True,
                    ):
                        artifact = artifact_index.get(artifact_id)
                        if (
                            artifact is None
                            or artifact.source_run_id != run_id
                            or artifact.extra
                            != {
                                "attempt_id": attempt_id,
                                "context_visibility": "engine_private",
                                "kind": f"data_transcript_{kind}",
                                "ordinal": ordinal,
                                "phase": phase,
                                "protocol": _PROTOCOL,
                            }
                            or not _sha(artifact.sha256)
                            or type(artifact.size) is not int
                            or artifact.size < 0
                        ):
                            errors.append(
                                f"{label} capture {artifact_id} is not exact"
                            )
                            continue
                        capture_artifacts.append(artifact)
                    expected_attempt_artifact_ids.extend(
                        replay["artifact_ids"]
                    )
                    if (
                        len(capture_artifacts) == 6
                        and len(proof_identities) == 6
                    ):
                        proof_identity = proof_identities[position]
                        result_sha, result_size = _canonical_sha(
                            {
                                "artifact_sha256": {
                                    artifact.extra["kind"]: artifact.sha256
                                    for artifact in capture_artifacts
                                },
                                "oracle_preissue_sha256": journal[
                                    "oracle_preissue_sha256"
                                ],
                                "protocol": _PROTOCOL,
                                "transport": {
                                    "clean_prefix": proof_identity[
                                        "clean_prefix"
                                    ],
                                    "network": "none",
                                    "one_shot": True,
                                    "sandbox_method": "run_clean_proof",
                                    "sandbox_run_id": proof_identity[
                                        "sandbox_run_id"
                                    ],
                                    "scope_fingerprint": proof_identity[
                                        "scope_fingerprint"
                                    ],
                                },
                            }
                        )
                        validation_sha, validation_size = _canonical_sha(
                            {
                                "complete_transport": True,
                                "network": "none",
                                "oracle_preissue_sha256": journal[
                                    "oracle_preissue_sha256"
                                ],
                                "protocol": _PROTOCOL,
                                "proof_identity": proof_identity,
                            }
                        )
                        if (
                            result_binding["sha256"] != result_sha
                            or result_binding["size_bytes"]
                            != result_size
                            or validation_binding["sha256"]
                            != validation_sha
                            or validation_binding["size_bytes"]
                            != validation_size
                        ):
                            errors.append(
                                f"{label} run {run_id} proof sidecar hash "
                                "is not reconstructable"
                            )
                else:
                    if any(
                        artifact_id in artifact_index
                        for artifact_id in replay["artifact_ids"]
                    ):
                        errors.append(
                            f"{label} failed run {run_id} retains captures"
                        )
                    result_sha, result_size = _canonical_sha(
                        {
                            "error": "data_transcript_execution_failed",
                            "failure_code": journal["failure_code"],
                            "protocol": _PROTOCOL,
                            "terminal": True,
                        }
                    )
                    validation_sha, validation_size = _canonical_sha(
                        {
                            "failure_code": journal["failure_code"],
                            "ok": False,
                            "protocol": _PROTOCOL,
                            "terminal": True,
                        }
                    )
                    if (
                        result_binding["sha256"] != result_sha
                        or result_binding["size_bytes"] != result_size
                        or validation_binding["sha256"]
                        != validation_sha
                        or validation_binding["size_bytes"]
                        != validation_size
                    ):
                        errors.append(
                            f"{label} run {run_id} failure sidecar hash "
                            "is not reconstructable"
                        )

        if status == "passed":
            evaluation_id = journal.get("evaluation_artifact_id")
            evaluation = artifact_index.get(evaluation_id)
            evaluation_matches = [
                item
                for item in state.artifacts
                if item.extra.get("attempt_id") == attempt_id
                and item.extra.get("kind")
                == "data_transcript_evaluation"
                and item.extra.get("protocol") == _PROTOCOL
            ]
            if (
                type(evaluation_id) is not str
                or not _sha(journal.get("evaluation_sha256"))
                or evaluation is None
                or len(evaluation_matches) != 1
                or evaluation_matches[0].id != evaluation_id
                or evaluation.sha256 != journal["evaluation_sha256"]
                or evaluation.source_run_id != run_ids[-1]
                or type(evaluation.size) is not int
                or evaluation.size < 1
                or evaluation.extra
                != {
                    "attempt_id": attempt_id,
                    "context_visibility": "engine_private",
                    "kind": "data_transcript_evaluation",
                    "ordinal": None,
                    "phase": None,
                    "protocol": _PROTOCOL,
                }
            ):
                errors.append(
                    f"{label} passed evaluation binding is not exact"
                )
            expected_attempt_artifact_ids.append(str(evaluation_id))

        actual_attempt_artifact_ids = {
            item.id
            for item in state.artifacts
            if item.extra.get("attempt_id") == attempt_id
            and item.extra.get("protocol") == _PROTOCOL
        }
        if actual_attempt_artifact_ids != set(
            expected_attempt_artifact_ids
        ):
            errors.append(f"{label} attempt artifact topology is not exact")

        if terminal is False:
            if experiment.status is not ExperimentStatus.RUNNING:
                errors.append(
                    f"{label} nonterminal parent experiment is not running"
                )
            continue

        if status == "passed":
            parent_evidence_artifact_ids = [
                replay["request_artifact"]["artifact_id"]
                for replay in replays
            ]
            parent_evidence_artifact_ids.extend(capture_ids)
            parent_evidence_artifact_ids.append(
                journal["evaluation_artifact_id"]
            )
            parent_evidence_artifact_ids.extend(
                artifact_id
                for replay in replays
                for artifact_id in (
                    replay["result_artifact"]["artifact_id"],
                    replay["validation_artifact"]["artifact_id"],
                )
            )
            expected_parent_status = ExperimentStatus.COMPLETED
            expected_parent_result = _typed_gate_result(
                passed=True,
                reason_codes=[journal["reason_code"]],
                evaluation_sha256=journal["evaluation_sha256"],
                evidence_artifact_ids=parent_evidence_artifact_ids,
                evidence_run_ids=list(run_ids),
                execution_error_type=None,
            )
        else:
            parent_evidence_artifact_ids = (
                []
                if shape == "reserved"
                else [
                    replay["request_artifact"]["artifact_id"]
                    for replay in replays
                ]
                + [
                    artifact_id
                    for replay in replays
                    for artifact_id in (
                        replay["result_artifact"]["artifact_id"],
                        replay["validation_artifact"]["artifact_id"],
                    )
                ]
            )
            expected_evidence_run_ids = (
                [] if shape == "reserved" else list(run_ids)
            )
            expected_parent_status = ExperimentStatus.FAILED
            expected_parent_result = _typed_gate_result(
                passed=False,
                reason_codes=["typed_gate_execution_error"],
                evaluation_sha256=None,
                evidence_artifact_ids=parent_evidence_artifact_ids,
                evidence_run_ids=expected_evidence_run_ids,
                execution_error_type=journal["execution_error_type"],
            )
        if (
            experiment.status is not expected_parent_status
            or experiment.result != expected_parent_result
            or experiment.extra.get("completed_at")
            != journal["completed_at"]
            or not set(parent_evidence_artifact_ids).issubset(
                experiment.artifact_ids
            )
        ):
            errors.append(
                f"{label} terminal parent experiment result is not exact"
            )

    for preissue in consumed_transcripts:
        preissue_id = preissue.get("preissue_id")
        if journal_preissue_ids.count(preissue_id) != 1:
            errors.append(
                "consumed transcript preissue does not own exactly one "
                "attempt journal"
            )
    return errors


__all__ = ["data_transcript_state_errors"]
