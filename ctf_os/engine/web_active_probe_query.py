"""Read-only physical revalidation for Web race/OOB active probes."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

from ctf_os.engine.web_active_probe import (
    WEB_ACTIVE_PROBE_MAX_ARTIFACT_BYTES,
    WEB_ACTIVE_PROBE_MAX_DRIVER_BYTES,
    WEB_ACTIVE_PROBE_MAX_REPORT_BYTES,
    WEB_ACTIVE_PROBE_MAX_SPEC_BYTES,
    classify_web_active_probe_report,
    evaluate_web_active_probe_records,
    parse_web_active_probe_driver,
    parse_web_active_probe_operator_spec,
)
from ctf_os.engine.web_active_probe_state import (
    WEB_ACTIVE_PROBE_STATE_GRAPHS_KEY,
    WEB_ACTIVE_PROBE_STATE_PREISSUES_KEY,
    WebActiveProbeStateContractError,
    validate_web_active_probe_state_graph,
)
from ctf_os.engine.web_impact_driver import (
    web_impact_target_binding_sha256,
)
from ctf_os.sandbox.files import read_bounded_regular
from ctf_os.stages.ingest import inventory_challenge
from ctf_os.store.atomic import StrictJSONError, strict_json_loads

if TYPE_CHECKING:
    from ctf_os.engine.challenge import ChallengeEngine
    from ctf_os.models import ChallengeIdentity


class WebActiveProbeQueryError(
    WebActiveProbeStateContractError
):
    """Physical active-probe evidence is unavailable or changed."""


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


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _strict_json(
    payload: bytes,
    maximum_bytes: int,
    *,
    require_canonical: bool = True,
) -> dict[str, object]:
    try:
        value = strict_json_loads(
            payload,
            max_bytes=maximum_bytes,
            max_depth=24,
        )
    except (StrictJSONError, UnicodeError, ValueError) as error:
        raise WebActiveProbeQueryError(
            "active_probe_physical_json_invalid"
        ) from error
    if type(value) is not dict or (
        require_canonical and payload != _canonical_bytes(value)
    ):
        raise WebActiveProbeQueryError(
            "active_probe_physical_json_not_canonical"
        )
    return value


def _read_artifact(
    root,
    artifact,
    *,
    maximum_bytes: int,
) -> bytes:
    try:
        return read_bounded_regular(
            root,
            artifact.path,
            maximum_bytes=maximum_bytes,
            expected_sha256=artifact.sha256,
            expected_size=artifact.size,
        )
    except (OSError, ValueError) as error:
        raise WebActiveProbeQueryError(
            "active_probe_artifact_revalidation_failed"
        ) from error


def _selected(
    state,
    attempt_id: str | None,
) -> tuple[str, dict[str, object], dict[str, object]]:
    preissues = state.extra.get(
        WEB_ACTIVE_PROBE_STATE_PREISSUES_KEY
    )
    graphs = state.extra.get(WEB_ACTIVE_PROBE_STATE_GRAPHS_KEY)
    if type(preissues) is not dict or type(graphs) is not dict:
        raise WebActiveProbeQueryError(
            "active_probe_graph_not_found"
        )
    selected_id = (
        attempt_id if attempt_id is not None else sorted(graphs)[-1]
        if graphs
        else None
    )
    if type(selected_id) is not str:
        raise WebActiveProbeQueryError(
            "active_probe_graph_not_found"
        )
    preissue = preissues.get(selected_id)
    wrapper = graphs.get(selected_id)
    if (
        type(preissue) is not dict
        or preissue.get("status") != "completed"
        or type(wrapper) is not dict
        or type(wrapper.get("graph")) is not dict
    ):
        raise WebActiveProbeQueryError(
            "active_probe_graph_not_complete"
        )
    return selected_id, preissue, wrapper


def validate_web_active_probe_query(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    attempt_id: str | None = None,
) -> dict[str, object]:
    """Recompute the six oracles from immutable source and exact bytes."""

    state = engine.store.load(identity, recover=False)
    state.validate()
    validate_web_active_probe_state_graph(state)
    selected_id, preissue, wrapper = _selected(
        state,
        attempt_id,
    )
    graph = wrapper["graph"]
    paths = engine.store.challenge_paths(identity)
    artifacts = {item.id: item for item in state.artifacts}

    def snapshot_payload(
        snapshot: dict[str, object],
        maximum_bytes: int,
    ) -> bytes:
        artifact = artifacts.get(snapshot["artifact_id"])
        if artifact is None:
            raise WebActiveProbeQueryError(
                "active_probe_snapshot_missing"
            )
        return _read_artifact(
            paths.root,
            artifact,
            maximum_bytes=maximum_bytes,
        )

    spec_payload = snapshot_payload(
        preissue["operator_spec"],
        WEB_ACTIVE_PROBE_MAX_SPEC_BYTES,
    )
    driver_payload = snapshot_payload(
        preissue["driver"],
        WEB_ACTIVE_PROBE_MAX_DRIVER_BYTES,
    )
    try:
        spec = parse_web_active_probe_operator_spec(spec_payload)
        driver = parse_web_active_probe_driver(
            driver_payload,
            operator_spec_payload=spec_payload,
        )
    except ValueError as error:
        raise WebActiveProbeQueryError(
            "active_probe_spec_driver_revalidation_failed"
        ) from error
    if (
        _sha256(spec_payload) != preissue["operator_spec_sha256"]
        or _sha256(driver_payload) != preissue["driver_sha256"]
        or engine.config.runtime.image_digest
        != preissue["runtime_image_digest"]
        or inventory_challenge(
            engine.challenge_input(identity)
        ).manifest_sha256
        != preissue["source_manifest_sha256"]
    ):
        raise WebActiveProbeQueryError(
            "active_probe_environment_rebound"
        )
    input_payloads = {
        snapshot["source_locator"]: snapshot_payload(
            snapshot,
            WEB_ACTIVE_PROBE_MAX_ARTIFACT_BYTES,
        )
        for snapshot in preissue["input_snapshots"]
    }
    expected_inputs = {}
    for step in (*driver.setup, driver.probe):
        for item in (step.route, step.body):
            if item is not None:
                expected_inputs[item.locator] = item
    if set(input_payloads) != set(expected_inputs) or any(
        _sha256(input_payloads[locator]) != item.sha256
        or len(input_payloads[locator]) != item.size_bytes
        for locator, item in expected_inputs.items()
    ):
        raise WebActiveProbeQueryError(
            "active_probe_input_snapshot_rebound"
        )
    targets = {item.id: item for item in state.targets}
    vulnerable = targets.get(preissue["vulnerable_target_id"])
    control = targets.get(preissue["control_target_id"])
    if vulnerable is None or control is None:
        raise WebActiveProbeQueryError(
            "active_probe_target_missing"
        )
    for target, expected in (
        (vulnerable, spec["vulnerable_target"]),
        (control, spec["control_target"]),
    ):
        if expected != {
            "binding_sha256": web_impact_target_binding_sha256(
                target
            ),
            "generation": target.generation,
            "kind": "allowlisted_http_origin_v1",
        }:
            raise WebActiveProbeQueryError(
                "active_probe_target_rebound"
            )

    records: list[dict[str, object]] = []
    physical_artifact_count = 0
    for ordinal, (issue, persisted_record) in enumerate(
        zip(
            preissue["issues"],
            graph["records"],
            strict=True,
        ),
        start=1,
    ):
        bindings = persisted_record["artifact_bindings"]
        report_artifact = artifacts[
            bindings["report"]["artifact_id"]
        ]
        report_payload = _read_artifact(
            paths.root,
            report_artifact,
            maximum_bytes=WEB_ACTIVE_PROBE_MAX_REPORT_BYTES,
        )
        report = _strict_json(
            report_payload,
            WEB_ACTIVE_PROBE_MAX_REPORT_BYTES,
        )
        classified = classify_web_active_probe_report(
            spec,
            report,
            target_kind=issue["target_kind"],
        )
        for key in (
            "mode",
            "passed",
            "reason_codes",
            "summary",
            "target_kind",
        ):
            if persisted_record[key] != classified[key]:
                raise WebActiveProbeQueryError(
                    "active_probe_classification_rebound"
                )
        if persisted_record["report_sha256"] != _sha256(
            report_payload
        ):
            raise WebActiveProbeQueryError(
                "active_probe_report_rebound"
            )
        timeline_artifact = artifacts[
            bindings["timeline"]["artifact_id"]
        ]
        timeline_payload = _read_artifact(
            paths.root,
            timeline_artifact,
            maximum_bytes=4 * 1024 * 1024,
        )
        _strict_json(timeline_payload, 4 * 1024 * 1024)
        if persisted_record["timeline_sha256"] != _sha256(
            timeline_payload
        ):
            raise WebActiveProbeQueryError(
                "active_probe_timeline_rebound"
            )
        outputs = []
        for binding in bindings["outputs"]:
            artifact = artifacts[binding["artifact_id"]]
            outputs.append(
                _read_artifact(
                    paths.root,
                    artifact,
                    maximum_bytes=(
                        WEB_ACTIVE_PROBE_MAX_ARTIFACT_BYTES
                    ),
                )
            )
            physical_artifact_count += 1
        if report["artifact_names"] != [
            (
                f"response-{index:04d}.bin"
                if preissue["mode"] == "race"
                else "trigger-response.bin"
                if index == 1
                else f"callback-{index - 1:02d}.bin"
            )
            for index in range(1, len(outputs) + 1)
        ]:
            raise WebActiveProbeQueryError(
                "active_probe_output_manifest_rebound"
            )
        report_outputs = (
            report["responses"]
            if preissue["mode"] == "race"
            else [report["trigger"], *report["callbacks"]]
        )
        if len(report_outputs) != len(outputs):
            raise WebActiveProbeQueryError(
                "active_probe_output_count_rebound"
            )
        for output, metadata in zip(
            outputs,
            report_outputs,
            strict=True,
        ):
            if (
                _sha256(output) != metadata["body_sha256"]
                or len(output) != metadata["body_size_bytes"]
            ):
                raise WebActiveProbeQueryError(
                    "active_probe_output_bytes_rebound"
                )
        for index, binding in enumerate(bindings["setup"]):
            artifact = artifacts[binding["artifact_id"]]
            payload = _read_artifact(
                paths.root,
                artifact,
                maximum_bytes=WEB_ACTIVE_PROBE_MAX_ARTIFACT_BYTES,
            )
            expected = spec["setup"][index]["expected_response"]
            if (
                binding["status"] != expected["status"]
                or _sha256(payload) != expected["body_sha256"]
                or len(payload) != expected["body_size_bytes"]
            ):
                raise WebActiveProbeQueryError(
                    "active_probe_setup_bytes_rebound"
                )
            physical_artifact_count += 1
        request_payload = read_bounded_regular(
            paths.root,
            preissue["request_bindings"][ordinal - 1]["path"],
            maximum_bytes=256 * 1024,
            expected_sha256=preissue["request_bindings"][
                ordinal - 1
            ]["sha256"],
            expected_size=preissue["request_bindings"][
                ordinal - 1
            ]["size_bytes"],
        )
        request = _strict_json(
            request_payload,
            256 * 1024,
            require_canonical=False,
        )
        if (
            request.get("issue") != issue
            or request.get("run_id") != issue["run_id"]
            or request.get("attempt_id") != selected_id
        ):
            raise WebActiveProbeQueryError(
                "active_probe_run_request_rebound"
            )
        run = next(
            item for item in state.runs if item.id == issue["run_id"]
        )
        sidecars = run.extra["web_active_probe_sidecars"]
        result = _strict_json(
            read_bounded_regular(
                paths.root,
                sidecars["result"]["path"],
                maximum_bytes=256 * 1024,
                expected_sha256=sidecars["result"]["sha256"],
                expected_size=sidecars["result"]["size_bytes"],
            ),
            256 * 1024,
            require_canonical=False,
        )
        validation = _strict_json(
            read_bounded_regular(
                paths.root,
                sidecars["validation"]["path"],
                maximum_bytes=256 * 1024,
                expected_sha256=sidecars["validation"]["sha256"],
                expected_size=sidecars["validation"]["size_bytes"],
            ),
            256 * 1024,
            require_canonical=False,
        )
        if (
            result.get("record_sha256")
            != _sha256(_canonical_bytes(persisted_record))
            or result.get("receipt_id") != issue["receipt_id"]
            or validation.get("ok") is not persisted_record["passed"]
            or validation.get("operator_spec_sha256")
            != preissue["operator_spec_sha256"]
        ):
            raise WebActiveProbeQueryError(
                "active_probe_run_sidecar_rebound"
            )
        records.append(persisted_record)
        physical_artifact_count += 2

    recomputed = evaluate_web_active_probe_records(
        operator_spec_sha256=preissue["operator_spec_sha256"],
        mode=preissue["mode"],
        records=tuple(records),
    )
    if recomputed != graph["evaluation"]:
        raise WebActiveProbeQueryError(
            "active_probe_evaluation_rebound"
        )
    evaluation_artifact = artifacts[
        preissue["evaluation_artifact_id"]
    ]
    evaluation_payload = _read_artifact(
        paths.root,
        evaluation_artifact,
        maximum_bytes=4 * 1024 * 1024,
    )
    if _strict_json(
        evaluation_payload,
        4 * 1024 * 1024,
    ) != recomputed:
        raise WebActiveProbeQueryError(
            "active_probe_evaluation_bytes_rebound"
        )
    return {
        "attempt_id": selected_id,
        "candidate_count": len(state.candidates),
        "confirmed": recomputed["confirmed"],
        "evaluation_sha256": recomputed["evaluation_sha256"],
        "graph_sha256": wrapper["graph_sha256"],
        "mode": preissue["mode"],
        "ok": True,
        "physical_artifact_count": (
            physical_artifact_count
            + 3
            + len(preissue["input_snapshots"])
        ),
        "raw_output_returned": False,
        "replay_count": len(records),
        "state_revision": state.revision,
        "submission_count": len(state.submissions),
    }


def query_web_active_probe(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    attempt_id: str | None = None,
) -> dict[str, object]:
    """Return only a bounded raw-free capsule after physical validation."""

    return validate_web_active_probe_query(
        engine,
        identity,
        attempt_id=attempt_id,
    )


__all__ = [
    "WebActiveProbeQueryError",
    "query_web_active_probe",
    "validate_web_active_probe_query",
]
