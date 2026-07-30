"""Deterministic contract for bounded Web race and OOB evidence.

The image-owned transport helper emits a value-free report.  This module
parses an exact operator specification and driver, classifies each helper
report against a non-LLM oracle, and requires three vulnerable plus three
patched/non-vulnerable repetitions.  It never sends a request itself.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from ctf_os.engine.web_impact import WEB_HTTP_METHODS, WEB_IDENTITY_ROLES
from ctf_os.engine.web_impact_driver import (
    WEB_IMPACT_DRIVER_MAX_LOCATOR_BYTES,
    WEB_IMPACT_DRIVER_MAX_ROUTE_BYTES,
    WebImpactDriverInput,
    WebImpactDriverStep,
)
from ctf_os.store.atomic import StrictJSONError, strict_json_loads


WEB_ACTIVE_PROBE_OPERATOR_PROTOCOL = (
    "ctfos.web.active_probe.operator.v1"
)
WEB_ACTIVE_PROBE_DRIVER_PROTOCOL = "ctfos.web.active_probe.driver.v1"
WEB_ACTIVE_PROBE_HELPER_PROTOCOL = (
    "ctfos.web.active_probe.helper.v1"
)
WEB_ACTIVE_PROBE_EVALUATION_PROTOCOL = (
    "ctfos.web.active_probe.evaluation.v1"
)
WEB_ACTIVE_PROBE_SCHEMA_VERSION = 1
WEB_ACTIVE_PROBE_REPETITIONS = 3
WEB_ACTIVE_PROBE_MAX_SPEC_BYTES = 128 * 1024
WEB_ACTIVE_PROBE_MAX_DRIVER_BYTES = 256 * 1024
WEB_ACTIVE_PROBE_MAX_SETUP_STEPS = 4
WEB_ACTIVE_PROBE_MAX_CONCURRENCY = 32
WEB_ACTIVE_PROBE_MAX_ATTEMPTS = 16
WEB_ACTIVE_PROBE_MAX_REQUESTS = 256
WEB_ACTIVE_PROBE_MAX_REPORT_BYTES = 8 * 1024 * 1024
WEB_ACTIVE_PROBE_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,255}$")
_NON_AUTHORITIES = {
    "automatic_submission_authorized": False,
    "candidate_authorized": False,
    "challenge_proof_satisfied": False,
    "flag_proven": False,
    "model_self_report_accepted": False,
    "submission_authorized": False,
}
_SPEC_KEYS = frozenset(
    {
        "control_target",
        "identity",
        "mode",
        "oracle",
        "probe",
        "protocol",
        "runtime_image_digest",
        "schema_version",
        "setup",
        "source_manifest_sha256",
        "transport",
        "vulnerable_target",
    }
)
_TARGET_KEYS = frozenset({"binding_sha256", "generation", "kind"})
_IDENTITY_KEYS = frozenset({"principal_binding_sha256", "role"})
_REQUEST_KEYS = frozenset(
    {
        "body_sha256",
        "body_size_bytes",
        "method",
        "request_shape_sha256",
        "route_sha256",
        "route_size_bytes",
    }
)
_SETUP_KEYS = frozenset({"expected_response", "request"})
_SIGNATURE_KEYS = frozenset(
    {"body_sha256", "body_size_bytes", "status"}
)
_RACE_ORACLE_KEYS = frozenset(
    {
        "control",
        "impact",
        "minimum_impact_count",
        "vulnerable_nonimpact",
    }
)
_OOB_ORACLE_KEYS = frozenset(
    {
        "callback",
        "control_trigger",
        "vulnerable_trigger",
    }
)
_CALLBACK_KEYS = frozenset(
    {"body_sha256", "body_size_bytes", "method"}
)
_RACE_TRANSPORT_KEYS = frozenset({"attempts", "concurrency"})
_OOB_TRANSPORT_KEYS = frozenset({"callback_timeout_seconds"})
_DRIVER_KEYS = frozenset(
    {
        "control_target_id",
        "operator_spec_sha256",
        "probe",
        "protocol",
        "schema_version",
        "setup",
        "vulnerable_target_id",
    }
)
_DRIVER_STEP_KEYS = frozenset(
    {
        "body",
        "follow",
        "insecure",
        "method",
        "ordinal",
        "route",
        "timeout_seconds",
    }
)
_DRIVER_INPUT_KEYS = frozenset({"locator", "sha256", "size_bytes"})


class WebActiveProbeError(ValueError):
    """Stable fail-closed active-probe contract error."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical_bytes(
    value: object,
    *,
    maximum_bytes: int,
) -> bytes:
    try:
        payload = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise WebActiveProbeError("canonical_json_invalid") from error
    if len(payload) > maximum_bytes:
        raise WebActiveProbeError("canonical_json_too_large")
    return payload


def _sha256(value: object, *, maximum_bytes: int) -> str:
    return hashlib.sha256(
        _canonical_bytes(value, maximum_bytes=maximum_bytes)
    ).hexdigest()


def _payload_sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _exact(
    value: object,
    keys: frozenset[str],
    code: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise WebActiveProbeError(code)
    return value


def _valid_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _valid_id(value: object) -> bool:
    return type(value) is str and _SAFE_ID.fullmatch(value) is not None


def _valid_target_id(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    return (
        bool(value)
        and len(encoded) <= 512
        and "\x00" not in value
        and all(
            ord(character) >= 0x20 and ord(character) != 0x7F
            for character in value
        )
    )


def _valid_size(value: object) -> bool:
    return (
        type(value) is int
        and 0 <= value <= WEB_ACTIVE_PROBE_MAX_ARTIFACT_BYTES
    )


def _validate_target(value: object, code: str) -> dict[str, object]:
    target = _exact(value, _TARGET_KEYS, code)
    if (
        target["kind"] != "allowlisted_http_origin_v1"
        or not _valid_sha256(target["binding_sha256"])
        or type(target["generation"]) is not int
        or target["generation"] < 1
    ):
        raise WebActiveProbeError(code)
    return target


def _validate_signature(
    value: object,
    code: str,
) -> dict[str, object]:
    signature = _exact(value, _SIGNATURE_KEYS, code)
    if (
        type(signature["status"]) is not int
        or not 100 <= signature["status"] <= 599
        or not _valid_sha256(signature["body_sha256"])
        or not _valid_size(signature["body_size_bytes"])
    ):
        raise WebActiveProbeError(code)
    return signature


def _validate_request(
    value: object,
    code: str,
) -> dict[str, object]:
    request = _exact(value, _REQUEST_KEYS, code)
    if (
        request["method"] not in WEB_HTTP_METHODS
        or not _valid_sha256(request["route_sha256"])
        or type(request["route_size_bytes"]) is not int
        or not 1
        <= request["route_size_bytes"]
        <= WEB_IMPACT_DRIVER_MAX_ROUTE_BYTES
        or (
            request["body_sha256"] is None
            and request["body_size_bytes"] is not None
        )
        or (
            request["body_sha256"] is not None
            and (
                not _valid_sha256(request["body_sha256"])
                or not _valid_size(request["body_size_bytes"])
            )
        )
        or not _valid_sha256(request["request_shape_sha256"])
    ):
        raise WebActiveProbeError(code)
    return request


def parse_web_active_probe_operator_spec(
    payload: bytes,
) -> dict[str, object]:
    """Parse one exact canonical raw-free operator specification."""

    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > WEB_ACTIVE_PROBE_MAX_SPEC_BYTES
    ):
        raise WebActiveProbeError("operator_spec_payload_invalid")
    try:
        value = strict_json_loads(
            payload,
            max_bytes=WEB_ACTIVE_PROBE_MAX_SPEC_BYTES,
            max_depth=16,
        )
    except (StrictJSONError, UnicodeError, ValueError) as error:
        raise WebActiveProbeError("operator_spec_json_invalid") from error
    root = _exact(value, _SPEC_KEYS, "operator_spec_schema_invalid")
    if (
        root["protocol"] != WEB_ACTIVE_PROBE_OPERATOR_PROTOCOL
        or type(root["schema_version"]) is not int
        or root["schema_version"] != WEB_ACTIVE_PROBE_SCHEMA_VERSION
        or root["mode"] not in {"oob", "race"}
        or not _valid_sha256(root["source_manifest_sha256"])
        or type(root["runtime_image_digest"]) is not str
        or _IMAGE_DIGEST.fullmatch(root["runtime_image_digest"]) is None
    ):
        raise WebActiveProbeError("operator_spec_header_invalid")
    vulnerable = _validate_target(
        root["vulnerable_target"],
        "operator_spec_vulnerable_target_invalid",
    )
    control = _validate_target(
        root["control_target"],
        "operator_spec_control_target_invalid",
    )
    if (
        vulnerable["binding_sha256"] == control["binding_sha256"]
    ):
        raise WebActiveProbeError("operator_spec_targets_not_distinct")
    identity = _exact(
        root["identity"],
        _IDENTITY_KEYS,
        "operator_spec_identity_invalid",
    )
    if (
        identity["role"] not in WEB_IDENTITY_ROLES
        or not _valid_sha256(identity["principal_binding_sha256"])
    ):
        raise WebActiveProbeError("operator_spec_identity_invalid")
    raw_setup = root["setup"]
    if (
        type(raw_setup) is not list
        or len(raw_setup) > WEB_ACTIVE_PROBE_MAX_SETUP_STEPS
    ):
        raise WebActiveProbeError("operator_spec_setup_invalid")
    setup: list[dict[str, object]] = []
    for ordinal, raw_step in enumerate(raw_setup, start=1):
        step = _exact(
            raw_step,
            _SETUP_KEYS,
            f"operator_spec_setup_{ordinal}_invalid",
        )
        setup.append(
            {
                "expected_response": _validate_signature(
                    step["expected_response"],
                    f"operator_spec_setup_{ordinal}_response_invalid",
                ),
                "request": _validate_request(
                    step["request"],
                    f"operator_spec_setup_{ordinal}_request_invalid",
                ),
            }
        )
    probe = _validate_request(
        root["probe"],
        "operator_spec_probe_invalid",
    )
    if probe["body_sha256"] is None:
        raise WebActiveProbeError("operator_spec_probe_body_required")
    mode = root["mode"]
    if mode == "race":
        transport = _exact(
            root["transport"],
            _RACE_TRANSPORT_KEYS,
            "operator_spec_race_transport_invalid",
        )
        if (
            type(transport["concurrency"]) is not int
            or not 2
            <= transport["concurrency"]
            <= WEB_ACTIVE_PROBE_MAX_CONCURRENCY
            or type(transport["attempts"]) is not int
            or not 1
            <= transport["attempts"]
            <= WEB_ACTIVE_PROBE_MAX_ATTEMPTS
            or transport["concurrency"] * transport["attempts"]
            > WEB_ACTIVE_PROBE_MAX_REQUESTS
        ):
            raise WebActiveProbeError(
                "operator_spec_race_transport_invalid"
            )
        oracle = _exact(
            root["oracle"],
            _RACE_ORACLE_KEYS,
            "operator_spec_race_oracle_invalid",
        )
        impact = _validate_signature(
            oracle["impact"],
            "operator_spec_race_impact_invalid",
        )
        vulnerable_nonimpact = _validate_signature(
            oracle["vulnerable_nonimpact"],
            "operator_spec_race_nonimpact_invalid",
        )
        control_signature = _validate_signature(
            oracle["control"],
            "operator_spec_race_control_invalid",
        )
        if (
            type(oracle["minimum_impact_count"]) is not int
            or not 1
            <= oracle["minimum_impact_count"]
            <= transport["concurrency"] * transport["attempts"]
            or len(
                {
                    _sha256(
                        item,
                        maximum_bytes=4096,
                    )
                    for item in (
                        impact,
                        vulnerable_nonimpact,
                        control_signature,
                    )
                }
            )
            != 3
        ):
            raise WebActiveProbeError(
                "operator_spec_race_oracle_invalid"
            )
    else:
        transport = _exact(
            root["transport"],
            _OOB_TRANSPORT_KEYS,
            "operator_spec_oob_transport_invalid",
        )
        if (
            type(transport["callback_timeout_seconds"]) is not int
            or not 1
            <= transport["callback_timeout_seconds"]
            <= 30
        ):
            raise WebActiveProbeError(
                "operator_spec_oob_transport_invalid"
            )
        oracle = _exact(
            root["oracle"],
            _OOB_ORACLE_KEYS,
            "operator_spec_oob_oracle_invalid",
        )
        callback = _exact(
            oracle["callback"],
            _CALLBACK_KEYS,
            "operator_spec_oob_callback_invalid",
        )
        if (
            callback["method"] not in WEB_HTTP_METHODS
            or not _valid_sha256(callback["body_sha256"])
            or not _valid_size(callback["body_size_bytes"])
        ):
            raise WebActiveProbeError(
                "operator_spec_oob_callback_invalid"
            )
        vulnerable_trigger = _validate_signature(
            oracle["vulnerable_trigger"],
            "operator_spec_oob_vulnerable_trigger_invalid",
        )
        control_trigger = _validate_signature(
            oracle["control_trigger"],
            "operator_spec_oob_control_trigger_invalid",
        )
        if vulnerable_trigger == control_trigger:
            raise WebActiveProbeError(
                "operator_spec_oob_differential_invalid"
            )
    canonical = {
        **root,
        "control_target": control,
        "identity": identity,
        "oracle": oracle,
        "probe": probe,
        "setup": setup,
        "transport": transport,
        "vulnerable_target": vulnerable,
    }
    if payload != _canonical_bytes(
        canonical,
        maximum_bytes=WEB_ACTIVE_PROBE_MAX_SPEC_BYTES,
    ):
        raise WebActiveProbeError("operator_spec_not_canonical")
    return canonical


def _valid_locator(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    if (
        not encoded
        or len(encoded) > WEB_IMPACT_DRIVER_MAX_LOCATOR_BYTES
        or value.startswith("/")
        or "\x00" in value
    ):
        return False
    return all(
        part not in {"", ".", ".."}
        for part in value.replace("\\", "/").split("/")
    )


def _parse_driver_input(
    value: object,
    *,
    maximum_bytes: int,
    code: str,
) -> WebImpactDriverInput:
    raw = _exact(value, _DRIVER_INPUT_KEYS, code)
    if (
        not _valid_locator(raw["locator"])
        or not _valid_sha256(raw["sha256"])
        or type(raw["size_bytes"]) is not int
        or not 0 <= raw["size_bytes"] <= maximum_bytes
    ):
        raise WebActiveProbeError(code)
    try:
        return WebImpactDriverInput(
            locator=raw["locator"],
            sha256=raw["sha256"],
            size_bytes=raw["size_bytes"],
        )
    except (TypeError, ValueError) as error:
        raise WebActiveProbeError(code) from error


def _parse_driver_step(
    value: object,
    *,
    ordinal: int,
    role: str,
    code: str,
) -> WebImpactDriverStep:
    raw = _exact(value, _DRIVER_STEP_KEYS, code)
    route = _parse_driver_input(
        raw["route"],
        maximum_bytes=WEB_IMPACT_DRIVER_MAX_ROUTE_BYTES,
        code=code,
    )
    body = (
        None
        if raw["body"] is None
        else _parse_driver_input(
            raw["body"],
            maximum_bytes=WEB_ACTIVE_PROBE_MAX_ARTIFACT_BYTES,
            code=code,
        )
    )
    try:
        step = WebImpactDriverStep(
            ordinal=raw["ordinal"],
            channel="http",
            role=role,
            method=raw["method"],
            route=route,
            body=body,
            follow=raw["follow"],
            insecure=raw["insecure"],
            timeout_seconds=raw["timeout_seconds"],
        )
    except (TypeError, ValueError) as error:
        raise WebActiveProbeError(code) from error
    if step.ordinal != ordinal:
        raise WebActiveProbeError(code)
    return step


@dataclass(frozen=True, slots=True)
class WebActiveProbeDriver:
    operator_spec_sha256: str
    vulnerable_target_id: str
    control_target_id: str
    setup: tuple[WebImpactDriverStep, ...]
    probe: WebImpactDriverStep

    def to_dict(self) -> dict[str, object]:
        def project(step: WebImpactDriverStep) -> dict[str, object]:
            value = step.to_dict()
            value.pop("channel")
            value.pop("role")
            return value

        return {
            "control_target_id": self.control_target_id,
            "operator_spec_sha256": self.operator_spec_sha256,
            "probe": project(self.probe),
            "protocol": WEB_ACTIVE_PROBE_DRIVER_PROTOCOL,
            "schema_version": WEB_ACTIVE_PROBE_SCHEMA_VERSION,
            "setup": [project(item) for item in self.setup],
            "vulnerable_target_id": self.vulnerable_target_id,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(
            self.to_dict(),
            maximum_bytes=WEB_ACTIVE_PROBE_MAX_DRIVER_BYTES,
        )

    @property
    def sha256(self) -> str:
        return _payload_sha256(self.canonical_bytes)


def parse_web_active_probe_driver(
    payload: bytes,
    *,
    operator_spec_payload: bytes,
) -> WebActiveProbeDriver:
    """Parse and bind the concrete setup/probe workspace locators."""

    spec = parse_web_active_probe_operator_spec(operator_spec_payload)
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > WEB_ACTIVE_PROBE_MAX_DRIVER_BYTES
    ):
        raise WebActiveProbeError("driver_payload_invalid")
    try:
        value = strict_json_loads(
            payload,
            max_bytes=WEB_ACTIVE_PROBE_MAX_DRIVER_BYTES,
            max_depth=16,
        )
    except (StrictJSONError, UnicodeError, ValueError) as error:
        raise WebActiveProbeError("driver_json_invalid") from error
    root = _exact(value, _DRIVER_KEYS, "driver_schema_invalid")
    if (
        root["protocol"] != WEB_ACTIVE_PROBE_DRIVER_PROTOCOL
        or type(root["schema_version"]) is not int
        or root["schema_version"] != WEB_ACTIVE_PROBE_SCHEMA_VERSION
        or root["operator_spec_sha256"]
        != _payload_sha256(operator_spec_payload)
        or not _valid_target_id(root["vulnerable_target_id"])
        or not _valid_target_id(root["control_target_id"])
        or root["vulnerable_target_id"] == root["control_target_id"]
    ):
        raise WebActiveProbeError("driver_header_invalid")
    raw_setup = root["setup"]
    if (
        type(raw_setup) is not list
        or len(raw_setup) != len(spec["setup"])
    ):
        raise WebActiveProbeError("driver_setup_invalid")
    setup = tuple(
        _parse_driver_step(
            item,
            ordinal=ordinal,
            role=spec["identity"]["role"],
            code=f"driver_setup_{ordinal}_invalid",
        )
        for ordinal, item in enumerate(raw_setup, start=1)
    )
    probe = _parse_driver_step(
        root["probe"],
        ordinal=len(setup) + 1,
        role=spec["identity"]["role"],
        code="driver_probe_invalid",
    )
    all_steps = (*setup, probe)
    if len(
        {
            item.route.locator
            for item in all_steps
        }
    ) != len(all_steps):
        raise WebActiveProbeError("driver_route_locator_reused")
    for ordinal, (step, expected) in enumerate(
        zip(setup, spec["setup"], strict=True),
        start=1,
    ):
        request = expected["request"]
        if (
            step.method != request["method"]
            or step.route.sha256 != request["route_sha256"]
            or step.route.size_bytes != request["route_size_bytes"]
            or (
                step.body.sha256 if step.body is not None else None
            )
            != request["body_sha256"]
            or (
                step.body.size_bytes if step.body is not None else None
            )
            != request["body_size_bytes"]
            or step.request_shape_sha256
            != request["request_shape_sha256"]
        ):
            raise WebActiveProbeError(
                f"driver_setup_{ordinal}_spec_mismatch"
            )
    expected_probe = spec["probe"]
    if (
        probe.method != expected_probe["method"]
        or probe.route.sha256 != expected_probe["route_sha256"]
        or probe.route.size_bytes
        != expected_probe["route_size_bytes"]
        or (probe.body.sha256 if probe.body is not None else None)
        != expected_probe["body_sha256"]
        or (
            probe.body.size_bytes
            if probe.body is not None
            else None
        )
        != expected_probe["body_size_bytes"]
        or probe.request_shape_sha256
        != expected_probe["request_shape_sha256"]
    ):
        raise WebActiveProbeError("driver_probe_spec_mismatch")
    driver = WebActiveProbeDriver(
        operator_spec_sha256=root["operator_spec_sha256"],
        vulnerable_target_id=root["vulnerable_target_id"],
        control_target_id=root["control_target_id"],
        setup=setup,
        probe=probe,
    )
    if payload != driver.canonical_bytes:
        raise WebActiveProbeError("driver_not_canonical")
    return driver


def _response_matches(
    value: dict[str, object],
    signature: dict[str, object],
) -> bool:
    return (
        value.get("status") == signature["status"]
        and value.get("body_sha256") == signature["body_sha256"]
        and value.get("body_size_bytes")
        == signature["body_size_bytes"]
    )


def classify_web_active_probe_report(
    spec: dict[str, object],
    report: object,
    *,
    target_kind: str,
) -> dict[str, object]:
    """Reduce one helper report to an exact raw-free oracle result."""

    if target_kind not in {"control", "vulnerable"}:
        raise WebActiveProbeError("report_target_kind_invalid")
    if (
        type(spec) is not dict
        or spec.get("protocol") != WEB_ACTIVE_PROBE_OPERATOR_PROTOCOL
        or type(report) is not dict
        or report.get("protocol") != WEB_ACTIVE_PROBE_HELPER_PROTOCOL
        or report.get("schema_version") != 1
        or report.get("mode") != spec["mode"]
        or report.get("session") != spec["identity"]["role"]
        or not _valid_sha256(
            report.get("cookie_transition_sha256")
        )
        or type(report.get("timeline_ordinal")) is not int
        or report["timeline_ordinal"] < 1
    ):
        raise WebActiveProbeError("helper_report_header_invalid")
    reasons: list[str] = []
    mode = spec["mode"]
    if mode == "race":
        transport = spec["transport"]
        oracle = spec["oracle"]
        responses = report.get("responses")
        expected_count = (
            transport["concurrency"] * transport["attempts"]
        )
        if (
            report.get("attempts") != transport["attempts"]
            or report.get("concurrency")
            != transport["concurrency"]
            or report.get("request_count") != expected_count
            or type(responses) is not list
            or len(responses) != expected_count
        ):
            raise WebActiveProbeError(
                "race_report_matrix_invalid"
            )
        impact_count = 0
        nonimpact_count = 0
        control_count = 0
        unexpected_count = 0
        truncated_count = 0
        for ordinal, response in enumerate(responses, start=1):
            expected_attempt = (
                (ordinal - 1) // transport["concurrency"]
            ) + 1
            expected_index = (
                (ordinal - 1) % transport["concurrency"]
            ) + 1
            if (
                type(response) is not dict
                or response.get("ordinal") != ordinal
                or response.get("attempt") != expected_attempt
                or response.get("index") != expected_index
                or not _valid_sha256(response.get("batch_sha256"))
                or not _valid_sha256(response.get("body_sha256"))
                or not _valid_size(response.get("body_size_bytes"))
                or type(response.get("status")) is not int
                or type(response.get("truncated")) is not bool
            ):
                raise WebActiveProbeError(
                    "race_report_response_invalid"
                )
            truncated_count += int(response["truncated"])
            if _response_matches(response, oracle["impact"]):
                impact_count += 1
            elif _response_matches(
                response,
                oracle["vulnerable_nonimpact"],
            ):
                nonimpact_count += 1
            elif _response_matches(response, oracle["control"]):
                control_count += 1
            else:
                unexpected_count += 1
        for attempt in range(1, transport["attempts"] + 1):
            offset = (attempt - 1) * transport["concurrency"]
            batch = responses[
                offset : offset + transport["concurrency"]
            ]
            expected_batch_sha256 = _sha256(
                [
                    {
                        key: value
                        for key, value in response.items()
                        if key != "batch_sha256"
                    }
                    for response in batch
                ],
                maximum_bytes=WEB_ACTIVE_PROBE_MAX_REPORT_BYTES,
            )
            if any(
                response["batch_sha256"]
                != expected_batch_sha256
                for response in batch
            ):
                raise WebActiveProbeError(
                    "race_report_batch_commitment_invalid"
                )
        if target_kind == "vulnerable":
            if impact_count < oracle["minimum_impact_count"]:
                reasons.append("vulnerable_impact_count_below_minimum")
            if control_count:
                reasons.append("vulnerable_emitted_control_signature")
            if impact_count + nonimpact_count != expected_count:
                reasons.append("vulnerable_response_set_not_exact")
        else:
            if impact_count:
                reasons.append("control_emitted_impact_signature")
            if control_count != expected_count:
                reasons.append("control_response_set_not_exact")
        if truncated_count:
            reasons.append("race_response_truncated")
        if unexpected_count:
            reasons.append("race_response_unexpected")
        summary = {
            "control_count": control_count,
            "impact_count": impact_count,
            "nonimpact_count": nonimpact_count,
            "request_count": expected_count,
            "truncated_count": truncated_count,
            "unexpected_count": unexpected_count,
        }
    else:
        oracle = spec["oracle"]
        callbacks = report.get("callbacks")
        trigger = report.get("trigger")
        if (
            type(callbacks) is not list
            or report.get("callback_count") != len(callbacks)
            or type(trigger) is not dict
            or type(trigger.get("truncated")) is not bool
            or not _valid_sha256(
                report.get("rendered_request_sha256")
            )
            or type(report.get("rendered_request_size_bytes"))
            is not int
        ):
            raise WebActiveProbeError("oob_report_shape_invalid")
        callback_matches = 0
        for callback in callbacks:
            if (
                type(callback) is not dict
                or set(callback)
                != {
                    "body_sha256",
                    "body_size_bytes",
                    "header_names_sha256",
                    "method",
                    "path_sha256",
                }
                or not _valid_sha256(
                    callback["header_names_sha256"]
                )
                or not _valid_sha256(callback["path_sha256"])
            ):
                raise WebActiveProbeError(
                    "oob_callback_record_invalid"
                )
            callback_matches += int(
                callback["method"] == oracle["callback"]["method"]
                and callback["body_sha256"]
                == oracle["callback"]["body_sha256"]
                and callback["body_size_bytes"]
                == oracle["callback"]["body_size_bytes"]
            )
        trigger_signature = (
            oracle["vulnerable_trigger"]
            if target_kind == "vulnerable"
            else oracle["control_trigger"]
        )
        if not _response_matches(trigger, trigger_signature):
            reasons.append("oob_trigger_response_mismatch")
        if trigger["truncated"]:
            reasons.append("oob_trigger_response_truncated")
        if target_kind == "vulnerable":
            if len(callbacks) != 1 or callback_matches != 1:
                reasons.append("oob_callback_not_exactly_reproduced")
        elif callbacks:
            reasons.append("oob_control_received_callback")
        summary = {
            "callback_count": len(callbacks),
            "callback_match_count": callback_matches,
            "rendered_request_sha256": report[
                "rendered_request_sha256"
            ],
            "rendered_request_size_bytes": report[
                "rendered_request_size_bytes"
            ],
            "trigger_body_sha256": trigger.get("body_sha256"),
            "trigger_body_size_bytes": trigger.get(
                "body_size_bytes"
            ),
            "trigger_status": trigger.get("status"),
        }
    return {
        "mode": mode,
        "passed": not reasons,
        "reason_codes": reasons,
        "summary": summary,
        "target_kind": target_kind,
    }


def evaluate_web_active_probe_records(
    *,
    operator_spec_sha256: str,
    mode: str,
    records: tuple[dict[str, object], ...],
) -> dict[str, object]:
    """Require the exact vulnerable3/control3 matrix to pass."""

    expected_kinds = (
        ("vulnerable",) * WEB_ACTIVE_PROBE_REPETITIONS
        + ("control",) * WEB_ACTIVE_PROBE_REPETITIONS
    )
    if (
        not _valid_sha256(operator_spec_sha256)
        or mode not in {"oob", "race"}
        or type(records) is not tuple
        or len(records) != len(expected_kinds)
    ):
        raise WebActiveProbeError("evaluation_records_invalid")
    used_ids: set[str] = set()
    reasons: list[str] = []
    for ordinal, (record, target_kind) in enumerate(
        zip(records, expected_kinds, strict=True),
        start=1,
    ):
        if (
            type(record) is not dict
            or record.get("ordinal") != ordinal
            or record.get("target_kind") != target_kind
            or record.get("mode") != mode
            or type(record.get("passed")) is not bool
            or type(record.get("reason_codes")) is not list
            or any(
                type(item) is not str
                for item in record["reason_codes"]
            )
            or not _valid_sha256(record.get("report_sha256"))
            or not _valid_sha256(record.get("timeline_sha256"))
            or not _valid_sha256(
                record.get("cookie_lineage_before_sha256")
            )
            or not _valid_sha256(
                record.get("cookie_lineage_after_sha256")
            )
            or not _valid_sha256(
                record.get("identity_epoch_sha256")
            )
            or not _valid_id(record.get("run_id"))
            or not _valid_id(record.get("receipt_id"))
            or record["run_id"] in used_ids
            or record["receipt_id"] in used_ids
        ):
            raise WebActiveProbeError(
                f"evaluation_record_{ordinal}_invalid"
            )
        used_ids.update(
            {record["run_id"], record["receipt_id"]}
        )
        if not record["passed"]:
            reasons.extend(
                f"{target_kind}_{ordinal}:{item}"
                for item in record["reason_codes"]
            )
    evaluation = {
        "authorities": {
            **_NON_AUTHORITIES,
            "executed_web_active_probe_fact_authorized": (
                not reasons
            ),
            "web_active_probe_oracle_satisfied": not reasons,
        },
        "confirmed": not reasons,
        "mode": mode,
        "operator_spec_sha256": operator_spec_sha256,
        "protocol": WEB_ACTIVE_PROBE_EVALUATION_PROTOCOL,
        "reason_codes": reasons,
        "record_commitments": [
            {
                "cookie_lineage_after_sha256": record[
                    "cookie_lineage_after_sha256"
                ],
                "cookie_lineage_before_sha256": record[
                    "cookie_lineage_before_sha256"
                ],
                "identity_epoch_sha256": record[
                    "identity_epoch_sha256"
                ],
                "ordinal": record["ordinal"],
                "receipt_id": record["receipt_id"],
                "report_sha256": record["report_sha256"],
                "run_id": record["run_id"],
                "target_kind": record["target_kind"],
                "timeline_sha256": record["timeline_sha256"],
            }
            for record in records
        ],
        "schema_version": WEB_ACTIVE_PROBE_SCHEMA_VERSION,
    }
    evaluation["evaluation_sha256"] = _sha256(
        evaluation,
        maximum_bytes=1024 * 1024,
    )
    return evaluation


__all__ = [
    "WEB_ACTIVE_PROBE_DRIVER_PROTOCOL",
    "WEB_ACTIVE_PROBE_EVALUATION_PROTOCOL",
    "WEB_ACTIVE_PROBE_HELPER_PROTOCOL",
    "WEB_ACTIVE_PROBE_MAX_ARTIFACT_BYTES",
    "WEB_ACTIVE_PROBE_MAX_DRIVER_BYTES",
    "WEB_ACTIVE_PROBE_MAX_REPORT_BYTES",
    "WEB_ACTIVE_PROBE_MAX_SPEC_BYTES",
    "WEB_ACTIVE_PROBE_OPERATOR_PROTOCOL",
    "WEB_ACTIVE_PROBE_REPETITIONS",
    "WEB_ACTIVE_PROBE_SCHEMA_VERSION",
    "WebActiveProbeDriver",
    "WebActiveProbeError",
    "classify_web_active_probe_report",
    "evaluate_web_active_probe_records",
    "parse_web_active_probe_driver",
    "parse_web_active_probe_operator_spec",
]
