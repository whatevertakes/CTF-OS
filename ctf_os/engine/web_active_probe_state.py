"""Exact persistence contract for Web race/OOB active-probe graphs."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Iterable

from ctf_os.engine.web_active_probe import (
    WEB_ACTIVE_PROBE_REPETITIONS,
    evaluate_web_active_probe_records,
)
from ctf_os.engine.web_impact_driver import (
    web_impact_target_binding_sha256,
)
from ctf_os.models import (
    ChallengeState,
    ExperimentKind,
    ExperimentStatus,
    Provenance,
    ReceiptOutcome,
    RunOrigin,
    RunStatus,
)


WEB_ACTIVE_PROBE_STATE_PROTOCOL = (
    "ctfos.web.active_probe.hotpath.v1"
)
WEB_ACTIVE_PROBE_STATE_SCHEMA_VERSION = 1
WEB_ACTIVE_PROBE_STATE_PREISSUES_KEY = (
    "web_active_probe_preissues"
)
WEB_ACTIVE_PROBE_STATE_GRAPHS_KEY = "web_active_probe_graphs"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,255}$")
_PREISSUE_KEYS = {
    "authorities",
    "attempt_id",
    "base_revision",
    "configuration_epoch",
    "control_target_id",
    "driver",
    "driver_sha256",
    "evaluation_artifact_id",
    "fact_id",
    "input_snapshots",
    "issues",
    "mode",
    "operator_spec",
    "operator_spec_sha256",
    "progress_id",
    "protocol",
    "request_bindings",
    "runtime_image_digest",
    "schema_version",
    "source_manifest_sha256",
    "status",
    "terminal",
    "vulnerable_target_id",
}
_ISSUE_KEYS = {
    "callback_token_sha256",
    "experiment_id",
    "identity_epoch_sha256",
    "lineage_nonce_sha256",
    "ordinal",
    "output_artifact_ids",
    "receipt_id",
    "report_artifact_id",
    "run_id",
    "setup_artifact_ids",
    "target_kind",
    "timeline_artifact_id",
}
_SNAPSHOT_KEYS = {
    "artifact_id",
    "path",
    "role",
    "sha256",
    "size_bytes",
    "source_locator",
}
_GRAPH_KEYS = {
    "authorities",
    "attempt_id",
    "committed_state_revision",
    "evaluation",
    "evaluation_artifact_id",
    "identity",
    "mode",
    "operator_spec_sha256",
    "preissue_sha256",
    "protocol",
    "records",
    "schema_version",
    "source_state_revision",
}
_RECORD_KEYS = {
    "artifact_bindings",
    "cookie_lineage_after_sha256",
    "cookie_lineage_before_sha256",
    "experiment_id",
    "identity_epoch_sha256",
    "lineage_nonce_sha256",
    "mode",
    "ordinal",
    "passed",
    "reason_codes",
    "receipt_id",
    "report_sha256",
    "request_sha256",
    "run_id",
    "setup_manifest_sha256",
    "summary",
    "target",
    "target_kind",
    "timeline_sha256",
}
_FALSE_AUTHORITIES = {
    "automatic_submission_authorized": False,
    "candidate_authorized": False,
    "challenge_proof_satisfied": False,
    "flag_proven": False,
    "submission_authorized": False,
}


class WebActiveProbeStateContractError(ValueError):
    """A durable active-probe graph is incomplete or rebound."""


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


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _is_id(value: object) -> bool:
    return type(value) is str and _SAFE_ID.fullmatch(value) is not None


def _is_safe_path(value: object) -> bool:
    if type(value) is not str or not value or value.startswith("/"):
        return False
    parts = value.split("/")
    return all(part not in {"", ".", ".."} for part in parts)


def _has_active_marker(value: object) -> bool:
    extra = getattr(value, "extra", None)
    if type(extra) is not dict:
        return False
    if (
        extra.get("protocol") == WEB_ACTIVE_PROBE_STATE_PROTOCOL
        or extra.get("engine_executor")
        == WEB_ACTIVE_PROBE_STATE_PROTOCOL
    ):
        return True
    nested = extra.get("web_active_probe")
    return type(nested) is dict


def _validate_snapshot(
    value: object,
    *,
    role: str,
) -> bool:
    return (
        type(value) is dict
        and set(value) == _SNAPSHOT_KEYS
        and _is_id(value.get("artifact_id"))
        and _is_safe_path(value.get("path"))
        and value.get("role") == role
        and _is_sha256(value.get("sha256"))
        and type(value.get("size_bytes")) is int
        and 0 <= value["size_bytes"] <= 64 * 1024 * 1024
        and type(value.get("source_locator")) is str
        and bool(value["source_locator"])
    )


def _validate_binding(value: object) -> bool:
    return (
        type(value) is dict
        and set(value)
        == {"artifact_id", "path", "sha256", "size_bytes"}
        and _is_id(value.get("artifact_id"))
        and _is_safe_path(value.get("path"))
        and _is_sha256(value.get("sha256"))
        and type(value.get("size_bytes")) is int
        and 0 <= value["size_bytes"] <= 64 * 1024 * 1024
    )


def _validate_setup_binding(value: object) -> bool:
    return (
        type(value) is dict
        and set(value)
        == {"artifact_id", "sha256", "size_bytes", "status"}
        and _is_id(value.get("artifact_id"))
        and _is_sha256(value.get("sha256"))
        and type(value.get("size_bytes")) is int
        and 0 <= value["size_bytes"] <= 64 * 1024 * 1024
        and type(value.get("status")) is int
        and 100 <= value["status"] <= 599
    )


def _validate_sidecar_binding(value: object) -> bool:
    return (
        type(value) is dict
        and set(value) == {"path", "sha256", "size_bytes"}
        and _is_safe_path(value.get("path"))
        and _is_sha256(value.get("sha256"))
        and type(value.get("size_bytes")) is int
        and 1 <= value["size_bytes"] <= 256 * 1024
    )


def _artifact_matches(
    artifact: object,
    binding: dict[str, object],
    *,
    require_path: bool,
) -> bool:
    return (
        artifact is not None
        and artifact.id == binding["artifact_id"]
        and artifact.sha256 == binding["sha256"]
        and artifact.size == binding["size_bytes"]
        and (
            not require_path
            or artifact.path == binding["path"]
        )
    )


def _issued_preissue_sha256(preissue: dict[str, object]) -> str:
    issued = copy.deepcopy(preissue)
    issued["status"] = "issued"
    issued["terminal"] = None
    return _sha256(issued)


def _validate_preissue(
    attempt_id: str,
    value: object,
) -> list[str]:
    prefix = f"Web active-probe preissue {attempt_id}"
    errors: list[str] = []
    if type(value) is not dict or set(value) != _PREISSUE_KEYS:
        return [f"{prefix} schema invalid"]
    if (
        value["attempt_id"] != attempt_id
        or not _is_id(attempt_id)
        or value["protocol"] != WEB_ACTIVE_PROBE_STATE_PROTOCOL
        or value["schema_version"]
        != WEB_ACTIVE_PROBE_STATE_SCHEMA_VERSION
        or value["mode"] not in {"oob", "race"}
        or value["status"]
        not in {"issued", "running", "completed", "failed"}
        or type(value["base_revision"]) is not int
        or value["base_revision"] < 0
        or type(value["configuration_epoch"]) is not int
        or value["configuration_epoch"] < 0
        or not _is_sha256(value["driver_sha256"])
        or not _is_sha256(value["operator_spec_sha256"])
        or not _is_sha256(value["source_manifest_sha256"])
        or type(value["runtime_image_digest"]) is not str
        or not value["runtime_image_digest"].startswith("sha256:")
        or value["vulnerable_target_id"]
        == value["control_target_id"]
        or not _is_id(value["evaluation_artifact_id"])
        or not _is_id(value["fact_id"])
        or not _is_id(value["progress_id"])
    ):
        errors.append(f"{prefix} header invalid")
    authorities = value["authorities"]
    if (
        type(authorities) is not dict
        or {
            key: authorities.get(key)
            for key in _FALSE_AUTHORITIES
        }
        != _FALSE_AUTHORITIES
        or authorities.get("executed_fact_authorized") is not False
        or set(authorities)
        != {*_FALSE_AUTHORITIES, "executed_fact_authorized"}
    ):
        errors.append(f"{prefix} authority widened")
    if not _validate_snapshot(
        value["operator_spec"],
        role="operator_spec",
    ) or not _validate_snapshot(value["driver"], role="driver"):
        errors.append(f"{prefix} spec/driver snapshot invalid")
    inputs = value["input_snapshots"]
    if (
        type(inputs) is not list
        or not inputs
        or any(
            not _validate_snapshot(item, role="driver_input")
            for item in inputs
        )
    ):
        errors.append(f"{prefix} input snapshots invalid")
    issues = value["issues"]
    expected_kinds = (
        ("vulnerable",) * WEB_ACTIVE_PROBE_REPETITIONS
        + ("control",) * WEB_ACTIVE_PROBE_REPETITIONS
    )
    if (
        type(issues) is not list
        or len(issues) != len(expected_kinds)
    ):
        errors.append(f"{prefix} replay width invalid")
        issues = []
    ids: list[str] = [
        value["evaluation_artifact_id"],
        value["fact_id"],
        value["progress_id"],
    ]
    for snapshot in (value["operator_spec"], value["driver"]):
        if type(snapshot) is dict:
            ids.append(snapshot.get("artifact_id"))
    if type(inputs) is list:
        ids.extend(
            item.get("artifact_id")
            for item in inputs
            if type(item) is dict
        )
    for ordinal, (issue, kind) in enumerate(
        zip(issues, expected_kinds, strict=True),
        start=1,
    ):
        if (
            type(issue) is not dict
            or set(issue) != _ISSUE_KEYS
            or issue.get("ordinal") != ordinal
            or issue.get("target_kind") != kind
            or not _is_sha256(issue.get("identity_epoch_sha256"))
            or not _is_sha256(issue.get("lineage_nonce_sha256"))
            or (
                value["mode"] == "oob"
                and not _is_sha256(
                    issue.get("callback_token_sha256")
                )
            )
            or (
                value["mode"] == "race"
                and issue.get("callback_token_sha256") is not None
            )
            or type(issue.get("setup_artifact_ids")) is not list
            or type(issue.get("output_artifact_ids")) is not list
            or any(
                not _is_id(item)
                for item in (
                    issue.get("experiment_id"),
                    issue.get("run_id"),
                    issue.get("receipt_id"),
                    issue.get("report_artifact_id"),
                    issue.get("timeline_artifact_id"),
                )
            )
            or any(
                not _is_id(item)
                for item in (
                    *issue.get("setup_artifact_ids", []),
                    *issue.get("output_artifact_ids", []),
                )
            )
        ):
            errors.append(f"{prefix} issue {ordinal} invalid")
            continue
        ids.extend(
            (
                issue["experiment_id"],
                issue["run_id"],
                issue["receipt_id"],
                issue["report_artifact_id"],
                issue["timeline_artifact_id"],
                *issue["setup_artifact_ids"],
                *issue["output_artifact_ids"],
            )
        )
    bindings = value["request_bindings"]
    if (
        type(bindings) is not list
        or len(bindings) != len(expected_kinds)
        or any(
            type(item) is not dict
            or set(item) != {"path", "sha256", "size_bytes"}
            or not _is_safe_path(item.get("path"))
            or not _is_sha256(item.get("sha256"))
            or type(item.get("size_bytes")) is not int
            or not 1 <= item["size_bytes"] <= 256 * 1024
            for item in bindings
        )
    ):
        errors.append(f"{prefix} request bindings invalid")
    typed_ids = [item for item in ids if type(item) is str]
    if len(typed_ids) != len(set(typed_ids)):
        errors.append(f"{prefix} identifiers collide")
    terminal = value["terminal"]
    if value["status"] in {"issued", "running"}:
        if terminal is not None:
            errors.append(f"{prefix} active terminal invalid")
    elif value["status"] == "failed":
        if (
            type(terminal) is not dict
            or set(terminal) != {"at", "error_type", "reason_code"}
            or terminal.get("reason_code")
            != "web_active_probe_interrupted"
        ):
            errors.append(f"{prefix} failure terminal invalid")
    else:
        if (
            type(terminal) is not dict
            or set(terminal)
            != {"at", "confirmed", "evaluation_sha256", "graph_sha256"}
            or type(terminal.get("confirmed")) is not bool
            or not _is_sha256(terminal.get("evaluation_sha256"))
            or not _is_sha256(terminal.get("graph_sha256"))
        ):
            errors.append(f"{prefix} completion terminal invalid")
    return errors


def _record_ids(
    records: Iterable[dict[str, object]],
) -> set[str]:
    values: set[str] = set()
    for record in records:
        for key in ("experiment_id", "run_id", "receipt_id"):
            value = record.get(key)
            if type(value) is str:
                values.add(value)
        bindings = record.get("artifact_bindings")
        if type(bindings) is not dict:
            continue
        for key in ("report", "timeline"):
            value = bindings.get(key)
            if type(value) is dict and type(
                value.get("artifact_id")
            ) is str:
                values.add(value["artifact_id"])
        for key in ("outputs", "setup"):
            group = bindings.get(key)
            if type(group) is list:
                values.update(
                    item["artifact_id"]
                    for item in group
                    if type(item) is dict
                    and type(item.get("artifact_id")) is str
                )
    return values


def _validate_graph(
    state: ChallengeState,
    attempt_id: str,
    preissue: dict[str, object],
    wrapper: object,
) -> list[str]:
    prefix = f"Web active-probe graph {attempt_id}"
    errors: list[str] = []
    if (
        type(wrapper) is not dict
        or set(wrapper)
        != {"graph", "graph_sha256", "protocol", "schema_version"}
        or wrapper.get("protocol")
        != WEB_ACTIVE_PROBE_STATE_PROTOCOL
        or wrapper.get("schema_version")
        != WEB_ACTIVE_PROBE_STATE_SCHEMA_VERSION
        or not _is_sha256(wrapper.get("graph_sha256"))
        or type(wrapper.get("graph")) is not dict
    ):
        return [f"{prefix} wrapper invalid"]
    graph = wrapper["graph"]
    if set(graph) != _GRAPH_KEYS:
        return [f"{prefix} schema invalid"]
    if _sha256(graph) != wrapper["graph_sha256"]:
        errors.append(f"{prefix} hash invalid")
    authorities = graph["authorities"]
    if (
        type(authorities) is not dict
        or {
            key: authorities.get(key)
            for key in _FALSE_AUTHORITIES
        }
        != _FALSE_AUTHORITIES
        or set(authorities)
        != {*_FALSE_AUTHORITIES, "web_active_probe_dependency_proven"}
        or type(
            authorities.get("web_active_probe_dependency_proven")
        )
        is not bool
    ):
        errors.append(f"{prefix} authority widened")
    if (
        graph["attempt_id"] != attempt_id
        or graph["protocol"] != WEB_ACTIVE_PROBE_STATE_PROTOCOL
        or graph["schema_version"]
        != WEB_ACTIVE_PROBE_STATE_SCHEMA_VERSION
        or graph["identity"] != state.identity.to_dict()
        or graph["mode"] != preissue["mode"]
        or graph["operator_spec_sha256"]
        != preissue["operator_spec_sha256"]
        or graph["evaluation_artifact_id"]
        != preissue["evaluation_artifact_id"]
        or graph["preissue_sha256"]
        != _issued_preissue_sha256(preissue)
        or type(graph["source_state_revision"]) is not int
        or graph["committed_state_revision"]
        != graph["source_state_revision"] + 1
        or graph["committed_state_revision"] > state.revision + 1
    ):
        errors.append(f"{prefix} immutable binding invalid")
    records = graph["records"]
    issues = preissue["issues"]
    bindings = preissue["request_bindings"]
    expected_kinds = (
        ("vulnerable",) * WEB_ACTIVE_PROBE_REPETITIONS
        + ("control",) * WEB_ACTIVE_PROBE_REPETITIONS
    )
    if (
        type(records) is not list
        or len(records) != len(expected_kinds)
    ):
        return [*errors, f"{prefix} replay records invalid"]
    try:
        recomputed = evaluate_web_active_probe_records(
            operator_spec_sha256=preissue[
                "operator_spec_sha256"
            ],
            mode=preissue["mode"],
            records=tuple(records),
        )
    except (TypeError, ValueError):
        recomputed = None
    if recomputed is None or graph["evaluation"] != recomputed:
        errors.append(f"{prefix} evaluation rebound")
    elif (
        authorities["web_active_probe_dependency_proven"]
        is not recomputed["confirmed"]
    ):
        errors.append(f"{prefix} evaluation authority rebound")

    experiments = {item.id: item for item in state.experiments}
    runs = {item.id: item for item in state.runs}
    receipts = {item.id: item for item in state.receipts}
    artifacts = {item.id: item for item in state.artifacts}
    targets = {item.id: item for item in state.targets}
    bound_ids: set[str] = set()
    for ordinal, (record, issue, request, kind) in enumerate(
        zip(records, issues, bindings, expected_kinds, strict=True),
        start=1,
    ):
        if type(record) is not dict or set(record) != _RECORD_KEYS:
            errors.append(f"{prefix} record {ordinal} schema invalid")
            continue
        target_id = (
            preissue["vulnerable_target_id"]
            if kind == "vulnerable"
            else preissue["control_target_id"]
        )
        target = targets.get(target_id)
        target_binding = record.get("target")
        if (
            record.get("ordinal") != ordinal
            or record.get("target_kind") != kind
            or record.get("mode") != preissue["mode"]
            or record.get("experiment_id")
            != issue["experiment_id"]
            or record.get("run_id") != issue["run_id"]
            or record.get("receipt_id") != issue["receipt_id"]
            or record.get("identity_epoch_sha256")
            != issue["identity_epoch_sha256"]
            or record.get("lineage_nonce_sha256")
            != issue["lineage_nonce_sha256"]
            or record.get("request_sha256") != request["sha256"]
            or type(record.get("passed")) is not bool
            or type(record.get("reason_codes")) is not list
            or any(
                type(item) is not str
                for item in record.get("reason_codes", [])
            )
            or type(record.get("summary")) is not dict
            or any(
                not _is_sha256(record.get(key))
                for key in (
                    "cookie_lineage_after_sha256",
                    "cookie_lineage_before_sha256",
                    "report_sha256",
                    "setup_manifest_sha256",
                    "timeline_sha256",
                )
            )
            or target is None
            or type(target_binding) is not dict
            or target_binding
            != {
                "binding_sha256": (
                    web_impact_target_binding_sha256(target)
                ),
                "generation": target.generation,
                "kind": "allowlisted_http_origin_v1",
                "target_id": target_id,
            }
        ):
            errors.append(f"{prefix} record {ordinal} binding invalid")
        artifact_bindings = record.get("artifact_bindings")
        if (
            type(artifact_bindings) is not dict
            or set(artifact_bindings)
            != {"outputs", "report", "setup", "timeline"}
            or type(artifact_bindings.get("outputs")) is not list
            or type(artifact_bindings.get("setup")) is not list
            or not _validate_binding(
                artifact_bindings.get("report")
            )
            or not _validate_binding(
                artifact_bindings.get("timeline")
            )
            or any(
                not _validate_binding(item)
                for item in artifact_bindings.get("outputs", [])
            )
            or any(
                not _validate_setup_binding(item)
                for item in artifact_bindings.get("setup", [])
            )
        ):
            errors.append(
                f"{prefix} record {ordinal} artifact bindings invalid"
            )
            continue
        output_bindings = artifact_bindings["outputs"]
        setup_bindings = artifact_bindings["setup"]
        if (
            [item["artifact_id"] for item in output_bindings]
            != issue["output_artifact_ids"]
            or [item["artifact_id"] for item in setup_bindings]
            != issue["setup_artifact_ids"]
            or artifact_bindings["report"]["artifact_id"]
            != issue["report_artifact_id"]
            or artifact_bindings["timeline"]["artifact_id"]
            != issue["timeline_artifact_id"]
            or record["report_sha256"]
            != artifact_bindings["report"]["sha256"]
            or record["timeline_sha256"]
            != artifact_bindings["timeline"]["sha256"]
            or record["setup_manifest_sha256"]
            != _sha256(setup_bindings)
        ):
            errors.append(
                f"{prefix} record {ordinal} artifact issue rebound"
            )
        for binding, require_path in (
            (artifact_bindings["report"], True),
            (artifact_bindings["timeline"], True),
            *((item, True) for item in output_bindings),
            *((item, False) for item in setup_bindings),
        ):
            if not _artifact_matches(
                artifacts.get(binding["artifact_id"]),
                binding,
                require_path=require_path,
            ):
                errors.append(
                    f"{prefix} record {ordinal} artifact descriptor rebound"
                )
        expected_artifact_ids = [
            *issue["setup_artifact_ids"],
            *issue["output_artifact_ids"],
            issue["report_artifact_id"],
            issue["timeline_artifact_id"],
        ]
        experiment = experiments.get(issue["experiment_id"])
        run = runs.get(issue["run_id"])
        receipt = receipts.get(issue["receipt_id"])
        record_sha256 = _sha256(record)
        if (
            experiment is None
            or experiment.status is not ExperimentStatus.COMPLETED
            or experiment.kind is not ExperimentKind.PROBE
            or experiment.result != {"web_active_probe": record}
            or experiment.artifact_ids != expected_artifact_ids
            or experiment.evidence_run_ids != [issue["run_id"]]
            or experiment.evidence_receipt_ids
            != [issue["receipt_id"]]
            or experiment.extra.get("engine_executor")
            != WEB_ACTIVE_PROBE_STATE_PROTOCOL
            or experiment.extra.get("web_active_probe")
            != {
                "attempt_id": attempt_id,
                "ordinal": ordinal,
                "record_sha256": record_sha256,
            }
        ):
            errors.append(f"{prefix} experiment {ordinal} rebound")
        sidecars = (
            run.extra.get("web_active_probe_sidecars")
            if run is not None
            else None
        )
        expected_run_root = request["path"].rsplit("/", 1)[0]
        if (
            run is None
            or run.status is not RunStatus.COMPLETED
            or run.base_revision != preissue["base_revision"]
            or run.role != "web_active_probe"
            or run.origin is not RunOrigin.OPERATOR_TOOL
            or run.configuration_epoch
            != preissue["configuration_epoch"]
            or run.request_path != request["path"]
            or run.result_path != f"{expected_run_root}/result.json"
            or run.validation_path
            != f"{expected_run_root}/validation.json"
            or set(run.extra)
            != {"web_active_probe", "web_active_probe_sidecars"}
            or run.extra.get("web_active_probe") != record
            or type(sidecars) is not dict
            or set(sidecars) != {"result", "validation"}
            or not _validate_sidecar_binding(sidecars.get("result"))
            or not _validate_sidecar_binding(
                sidecars.get("validation")
            )
            or sidecars["result"]["path"] != run.result_path
            or sidecars["validation"]["path"]
            != run.validation_path
        ):
            errors.append(f"{prefix} run {ordinal} rebound")
        if (
            receipt is None
            or receipt.experiment_id != issue["experiment_id"]
            or receipt.run_id != issue["run_id"]
            or receipt.outcome is not ReceiptOutcome.SUCCEEDED
            or receipt.exit_code != 0
            or set(receipt.extra) != {"web_active_probe"}
            or receipt.extra.get("web_active_probe")
            != {
                "record_sha256": record_sha256,
                "report_artifact_id": issue["report_artifact_id"],
                "timeline_artifact_id": issue[
                    "timeline_artifact_id"
                ],
            }
        ):
            errors.append(f"{prefix} receipt {ordinal} rebound")
        bound_ids.update(
            {
                issue["experiment_id"],
                issue["run_id"],
                issue["receipt_id"],
                *expected_artifact_ids,
            }
        )

    for snapshot, role in (
        (preissue["operator_spec"], "operator_spec"),
        (preissue["driver"], "driver"),
        *((item, "driver_input") for item in preissue["input_snapshots"]),
    ):
        artifact = artifacts.get(snapshot["artifact_id"])
        if (
            artifact is None
            or artifact.path != snapshot["path"]
            or artifact.sha256 != snapshot["sha256"]
            or artifact.size != snapshot["size_bytes"]
            or artifact.extra
            != {
                "context_visibility": "engine_private",
                "kind": f"web_active_probe_{role}_snapshot",
                "protocol": WEB_ACTIVE_PROBE_STATE_PROTOCOL,
                "source_locator": snapshot["source_locator"],
            }
        ):
            errors.append(f"{prefix} {role} snapshot rebound")
        bound_ids.add(snapshot["artifact_id"])
    evaluation_artifact = artifacts.get(
        preissue["evaluation_artifact_id"]
    )
    if (
        recomputed is None
        or evaluation_artifact is None
        or evaluation_artifact.sha256 != _sha256(recomputed)
        or evaluation_artifact.extra
        != {
            "context_visibility": "engine_private",
            "kind": "web_active_probe_evaluation",
            "protocol": WEB_ACTIVE_PROBE_STATE_PROTOCOL,
        }
    ):
        errors.append(f"{prefix} evaluation artifact rebound")
    bound_ids.add(preissue["evaluation_artifact_id"])

    confirmed = (
        recomputed is not None and recomputed["confirmed"] is True
    )
    facts = {item.id: item for item in state.facts}
    progress = {item.id: item for item in state.progress_markers}
    fact = facts.get(preissue["fact_id"])
    marker = progress.get(preissue["progress_id"])
    if confirmed:
        if (
            fact is None
            or fact.provenance is not Provenance.EXECUTED
            or fact.artifact_id != preissue["evaluation_artifact_id"]
            or fact.extra.get("web_active_probe")
            != {
                "attempt_id": attempt_id,
                "evaluation_sha256": recomputed[
                    "evaluation_sha256"
                ],
                "graph_sha256": wrapper["graph_sha256"],
                "mode": preissue["mode"],
                "protocol": WEB_ACTIVE_PROBE_STATE_PROTOCOL,
            }
        ):
            errors.append(f"{prefix} executed fact rebound")
        if (
            marker is None
            or marker.artifact_ids
            != [preissue["evaluation_artifact_id"]]
            or marker.extra.get("adapter_marker")
            != "web_active_probe_confirmed"
            or marker.extra.get("automatic_submission_authorized")
            is not False
            or marker.extra.get("evaluation_sha256")
            != recomputed["evaluation_sha256"]
            or marker.extra.get("graph_sha256")
            != wrapper["graph_sha256"]
            or marker.extra.get("protocol")
            != WEB_ACTIVE_PROBE_STATE_PROTOCOL
        ):
            errors.append(f"{prefix} progress marker rebound")
        bound_ids.update({preissue["fact_id"], preissue["progress_id"]})
    elif fact is not None or marker is not None:
        errors.append(f"{prefix} rejected graph granted progress")
    terminal = preissue["terminal"]
    if (
        terminal.get("confirmed") is not confirmed
        or terminal.get("evaluation_sha256")
        != (
            recomputed.get("evaluation_sha256")
            if recomputed is not None
            else None
        )
        or terminal.get("graph_sha256") != wrapper["graph_sha256"]
    ):
        errors.append(f"{prefix} completion terminal rebound")
    return errors


def web_active_probe_state_graph_errors(
    state: ChallengeState,
) -> list[str]:
    """Return relational errors for all active-probe preissues and graphs."""

    preissues = state.extra.get(WEB_ACTIVE_PROBE_STATE_PREISSUES_KEY)
    graphs = state.extra.get(WEB_ACTIVE_PROBE_STATE_GRAPHS_KEY)
    if preissues is None and graphs is None:
        return []
    if state.category != "web":
        return ["Web active-probe graph requires Web category"]
    errors: list[str] = []
    if type(preissues) is not dict:
        return ["Web active-probe preissue journal invalid"]
    if graphs is None:
        graphs = {}
    if type(graphs) is not dict:
        return ["Web active-probe graph journal invalid"]
    for attempt_id, preissue in preissues.items():
        if type(attempt_id) is not str:
            errors.append("Web active-probe attempt id invalid")
            continue
        errors.extend(_validate_preissue(attempt_id, preissue))
        if type(preissue) is not dict:
            continue
        graph = graphs.get(attempt_id)
        if preissue.get("status") == "completed":
            if graph is None:
                errors.append(
                    f"Web active-probe graph {attempt_id} missing"
                )
            else:
                errors.extend(
                    _validate_graph(
                        state,
                        attempt_id,
                        preissue,
                        graph,
                    )
                )
        elif graph is not None:
            errors.append(
                f"Web active-probe graph {attempt_id} premature"
            )
    for attempt_id in graphs:
        if attempt_id not in preissues:
            errors.append(
                f"orphan Web active-probe graph {attempt_id}"
            )

    bound = set()
    for attempt_id, wrapper in graphs.items():
        graph = (
            wrapper.get("graph")
            if type(wrapper) is dict
            else None
        )
        if type(graph) is dict and type(graph.get("records")) is list:
            bound.update(
                _record_ids(
                    item
                    for item in graph["records"]
                    if type(item) is dict
                )
            )
        preissue = preissues.get(attempt_id)
        if type(preissue) is dict:
            for snapshot in (
                preissue.get("operator_spec"),
                preissue.get("driver"),
                *(preissue.get("input_snapshots") or []),
            ):
                if type(snapshot) is dict and type(
                    snapshot.get("artifact_id")
                ) is str:
                    bound.add(snapshot["artifact_id"])
            for key in (
                "evaluation_artifact_id",
                "fact_id",
                "progress_id",
            ):
                if type(preissue.get(key)) is str:
                    bound.add(preissue[key])
    for collection, kind in (
        (state.experiments, "experiment"),
        (state.runs, "run"),
        (state.receipts, "receipt"),
        (state.artifacts, "artifact"),
        (state.facts, "fact"),
        (state.progress_markers, "progress"),
        (state.candidates, "candidate"),
        (state.submissions, "submission"),
    ):
        for record in collection:
            if _has_active_marker(record) and record.id not in bound:
                errors.append(
                    f"orphan Web active-probe {kind} {record.id}"
                )
    return errors


def validate_web_active_probe_state_graph(
    state: ChallengeState,
) -> None:
    """Raise one stable error for an invalid durable active-probe graph."""

    errors = web_active_probe_state_graph_errors(state)
    if errors:
        raise WebActiveProbeStateContractError(errors[0])


__all__ = [
    "WEB_ACTIVE_PROBE_STATE_GRAPHS_KEY",
    "WEB_ACTIVE_PROBE_STATE_PREISSUES_KEY",
    "WEB_ACTIVE_PROBE_STATE_PROTOCOL",
    "WEB_ACTIVE_PROBE_STATE_SCHEMA_VERSION",
    "WebActiveProbeStateContractError",
    "validate_web_active_probe_state_graph",
    "web_active_probe_state_graph_errors",
]
