"""Strict value-free execution manifest for the Web impact hot path.

The semantic Web specification intentionally contains only commitments, so it
cannot tell the engine which concrete route or request body to replay.  This
module supplies that missing execution contract without placing route values,
request bodies, cookies, credentials, tokens, or expected responses in
``state.json``.

Every concrete route/body is named by a challenge-scoped locator and an exact
SHA-256/size commitment.  The engine snapshots those files before it issues any
replay.  Only the image-owned HTTP/browser helpers are permitted to consume the
snapshots.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from ctf_os.engine.web_impact import (
    WEB_HTTP_METHODS,
    WEB_IDENTITY_ROLES,
    WEB_IMPACT_MAX_ARTIFACT_BYTES,
    WEB_IMPACT_MAX_TIMELINE_STEPS,
    WEB_TIMELINE_CHANNELS,
    WebTimelineStep,
)
from ctf_os.engine.web_impact_execution import (
    WEB_IMPACT_OPERATOR_SPEC_MAX_BYTES,
)
from ctf_os.models import TargetRecord, TargetStatus
from ctf_os.store.atomic import StrictJSONError, strict_json_loads


WEB_IMPACT_DRIVER_PROTOCOL = "ctfos.web.impact.driver.v1"
WEB_IMPACT_DRIVER_SCHEMA_VERSION = 1
WEB_IMPACT_DRIVER_MAX_BYTES = 256 * 1024
WEB_IMPACT_DRIVER_MAX_LOCATOR_BYTES = 4096
WEB_IMPACT_DRIVER_MAX_ROUTE_BYTES = 16 * 1024
WEB_IMPACT_DRIVER_MAX_TIMEOUT_SECONDS = 300
WEB_IMPACT_TARGET_BINDING_PROTOCOL = "ctfos.web.target.binding.v1"
WEB_IMPACT_REQUEST_SHAPE_PROTOCOL = "ctfos.web.request.shape.v1"
WEB_IMPACT_TRACE_CONTRACT_PROTOCOL = "ctfos.web.runtime.join.v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,255}$")
_ROOT_KEYS = frozenset(
    {
        "control_target_id",
        "operator_spec_sha256",
        "protocol",
        "schema_version",
        "steps",
        "vulnerable_target_id",
    }
)
_STEP_KEYS = frozenset(
    {
        "body",
        "channel",
        "follow",
        "insecure",
        "method",
        "ordinal",
        "role",
        "route",
        "timeout_seconds",
    }
)
_INPUT_KEYS = frozenset({"locator", "sha256", "size_bytes"})


class WebImpactDriverError(ValueError):
    """The concrete replay manifest is unsafe or does not match its hashes."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical_json_bytes(value: object) -> bytes:
    try:
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
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise WebImpactDriverError("canonical_json_invalid") from error


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _exact_dict(
    value: object,
    keys: frozenset[str],
    code: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise WebImpactDriverError(code)
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
        or "\x00" in value
        or value.startswith("/")
    ):
        return False
    parts = value.replace("\\", "/").split("/")
    return all(part not in {"", ".", ".."} for part in parts)


@dataclass(frozen=True, slots=True)
class WebImpactDriverInput:
    locator: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        if (
            not _valid_locator(self.locator)
            or not _valid_sha256(self.sha256)
            or type(self.size_bytes) is not int
            or not 0 <= self.size_bytes <= WEB_IMPACT_MAX_ARTIFACT_BYTES
        ):
            raise ValueError("driver_input_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "locator": self.locator,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True, slots=True)
class WebImpactDriverStep:
    ordinal: int
    channel: str
    role: str
    method: str
    route: WebImpactDriverInput
    body: WebImpactDriverInput | None
    follow: bool
    insecure: bool
    timeout_seconds: int

    def __post_init__(self) -> None:
        if (
            type(self.ordinal) is not int
            or not 1 <= self.ordinal <= WEB_IMPACT_MAX_TIMELINE_STEPS
            or self.channel not in WEB_TIMELINE_CHANNELS
            or self.role not in WEB_IDENTITY_ROLES
            or self.method not in WEB_HTTP_METHODS
            or type(self.route) is not WebImpactDriverInput
            or self.route.size_bytes > WEB_IMPACT_DRIVER_MAX_ROUTE_BYTES
            or (
                self.body is not None
                and type(self.body) is not WebImpactDriverInput
            )
            or type(self.follow) is not bool
            or type(self.insecure) is not bool
            or type(self.timeout_seconds) is not int
            or not 1
            <= self.timeout_seconds
            <= WEB_IMPACT_DRIVER_MAX_TIMEOUT_SECONDS
            or (
                self.channel == "browser"
                and (
                    self.method != "GET"
                    or self.body is not None
                    or self.follow is not False
                )
            )
        ):
            raise ValueError("driver_step_invalid")

    @property
    def route_binding_sha256(self) -> str:
        return self.route.sha256

    @property
    def request_shape_sha256(self) -> str:
        return _sha256(
            _canonical_json_bytes(
                {
                    "body": (
                        {
                            "sha256": self.body.sha256,
                            "size_bytes": self.body.size_bytes,
                        }
                        if self.body is not None
                        else None
                    ),
                    "channel": self.channel,
                    "follow": self.follow,
                    "insecure": self.insecure,
                    "method": self.method,
                    "protocol": WEB_IMPACT_REQUEST_SHAPE_PROTOCOL,
                    "role": self.role,
                    "route_sha256": self.route.sha256,
                    "route_size_bytes": self.route.size_bytes,
                    "timeout_seconds": self.timeout_seconds,
                }
            )
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "body": self.body.to_dict() if self.body is not None else None,
            "channel": self.channel,
            "follow": self.follow,
            "insecure": self.insecure,
            "method": self.method,
            "ordinal": self.ordinal,
            "role": self.role,
            "route": self.route.to_dict(),
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass(frozen=True, slots=True)
class WebImpactDriverManifest:
    operator_spec_sha256: str
    vulnerable_target_id: str
    control_target_id: str | None
    steps: tuple[WebImpactDriverStep, ...]

    def __post_init__(self) -> None:
        if (
            not _valid_sha256(self.operator_spec_sha256)
            or not _valid_target_id(self.vulnerable_target_id)
            or (
                self.control_target_id is not None
                and (
                    not _valid_target_id(self.control_target_id)
                    or self.control_target_id
                    == self.vulnerable_target_id
                )
            )
            or type(self.steps) is not tuple
            or not 2 <= len(self.steps) <= WEB_IMPACT_MAX_TIMELINE_STEPS
            or any(
                type(item) is not WebImpactDriverStep
                for item in self.steps
            )
            or tuple(item.ordinal for item in self.steps)
            != tuple(range(1, len(self.steps) + 1))
            or {item.channel for item in self.steps}
            != WEB_TIMELINE_CHANNELS
        ):
            raise ValueError("driver_manifest_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "control_target_id": self.control_target_id,
            "operator_spec_sha256": self.operator_spec_sha256,
            "protocol": WEB_IMPACT_DRIVER_PROTOCOL,
            "schema_version": WEB_IMPACT_DRIVER_SCHEMA_VERSION,
            "steps": [item.to_dict() for item in self.steps],
            "vulnerable_target_id": self.vulnerable_target_id,
        }

    @property
    def canonical_bytes(self) -> bytes:
        payload = _canonical_json_bytes(self.to_dict())
        if len(payload) > WEB_IMPACT_DRIVER_MAX_BYTES:
            raise ValueError("driver_manifest_size_exceeded")
        return payload

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)

    def validate_timeline(
        self,
        timeline: tuple[WebTimelineStep, ...],
    ) -> None:
        if (
            type(timeline) is not tuple
            or len(timeline) != len(self.steps)
        ):
            raise WebImpactDriverError("driver_timeline_count_mismatch")
        for expected, concrete in zip(
            timeline,
            self.steps,
            strict=True,
        ):
            if (
                type(expected) is not WebTimelineStep
                or expected.ordinal != concrete.ordinal
                or expected.channel != concrete.channel
                or expected.role != concrete.role
                or expected.method != concrete.method
                or expected.route_binding_sha256
                != concrete.route_binding_sha256
                or expected.request_shape_sha256
                != concrete.request_shape_sha256
            ):
                raise WebImpactDriverError(
                    f"driver_timeline_step_{concrete.ordinal}_mismatch"
                )


def _parse_input(
    value: object,
    *,
    maximum: int,
    code: str,
) -> WebImpactDriverInput:
    raw = _exact_dict(value, _INPUT_KEYS, code)
    try:
        result = WebImpactDriverInput(
            locator=raw["locator"],
            sha256=raw["sha256"],
            size_bytes=raw["size_bytes"],
        )
    except (TypeError, ValueError) as error:
        raise WebImpactDriverError(code) from error
    if result.size_bytes > maximum:
        raise WebImpactDriverError(code)
    return result


def parse_web_impact_driver_manifest(
    payload: bytes,
    *,
    operator_spec_payload: bytes,
) -> WebImpactDriverManifest:
    """Parse an exact canonical, value-free replay driver."""

    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > WEB_IMPACT_DRIVER_MAX_BYTES
        or type(operator_spec_payload) is not bytes
        or not operator_spec_payload
        or len(operator_spec_payload)
        > WEB_IMPACT_OPERATOR_SPEC_MAX_BYTES
    ):
        raise WebImpactDriverError("driver_payload_invalid")
    try:
        parsed = strict_json_loads(
            payload,
            max_bytes=WEB_IMPACT_DRIVER_MAX_BYTES,
            max_depth=12,
        )
    except (StrictJSONError, UnicodeError, ValueError) as error:
        raise WebImpactDriverError("driver_json_invalid") from error
    root = _exact_dict(
        parsed,
        _ROOT_KEYS,
        "driver_schema_invalid",
    )
    if (
        root["protocol"] != WEB_IMPACT_DRIVER_PROTOCOL
        or type(root["schema_version"]) is not int
        or root["schema_version"]
        != WEB_IMPACT_DRIVER_SCHEMA_VERSION
        or root["operator_spec_sha256"]
        != _sha256(operator_spec_payload)
    ):
        raise WebImpactDriverError("driver_header_invalid")
    raw_steps = root["steps"]
    if (
        type(raw_steps) is not list
        or not 2 <= len(raw_steps) <= WEB_IMPACT_MAX_TIMELINE_STEPS
    ):
        raise WebImpactDriverError("driver_steps_invalid")
    steps: list[WebImpactDriverStep] = []
    for position, value in enumerate(raw_steps, start=1):
        raw = _exact_dict(
            value,
            _STEP_KEYS,
            f"driver_step_{position}_schema_invalid",
        )
        route = _parse_input(
            raw["route"],
            maximum=WEB_IMPACT_DRIVER_MAX_ROUTE_BYTES,
            code=f"driver_step_{position}_route_invalid",
        )
        body = (
            None
            if raw["body"] is None
            else _parse_input(
                raw["body"],
                maximum=WEB_IMPACT_MAX_ARTIFACT_BYTES,
                code=f"driver_step_{position}_body_invalid",
            )
        )
        try:
            steps.append(
                WebImpactDriverStep(
                    ordinal=raw["ordinal"],
                    channel=raw["channel"],
                    role=raw["role"],
                    method=raw["method"],
                    route=route,
                    body=body,
                    follow=raw["follow"],
                    insecure=raw["insecure"],
                    timeout_seconds=raw["timeout_seconds"],
                )
            )
        except (TypeError, ValueError) as error:
            raise WebImpactDriverError(
                f"driver_step_{position}_invalid"
            ) from error
    try:
        manifest = WebImpactDriverManifest(
            operator_spec_sha256=root["operator_spec_sha256"],
            vulnerable_target_id=root["vulnerable_target_id"],
            control_target_id=root["control_target_id"],
            steps=tuple(steps),
        )
    except (TypeError, ValueError) as error:
        raise WebImpactDriverError("driver_manifest_invalid") from error
    if payload != manifest.canonical_bytes:
        raise WebImpactDriverError("driver_not_canonical")
    return manifest


def web_impact_target_binding_sha256(target: TargetRecord) -> str:
    """Bind exactly the currently approved target generation and boundary."""

    if (
        type(target) is not TargetRecord
        or not _valid_target_id(target.id)
        or type(target.endpoint) is not str
        or not target.endpoint
        or target.status is not TargetStatus.ACTIVE
        or target.enforcement not in {"proxy", "builtin"}
        or type(target.docker_network) is not str
        or not target.docker_network
        or type(target.generation) is not int
        or target.generation < 1
    ):
        raise WebImpactDriverError("target_record_invalid")
    document = {
        "docker_network": target.docker_network,
        "endpoint": target.endpoint,
        "enforcement": target.enforcement,
        "generation": target.generation,
        "id": target.id,
        "protocol": WEB_IMPACT_TARGET_BINDING_PROTOCOL,
        "status": target.status.value,
    }
    if target.enforcement == "builtin":
        document["builtin_egress"] = target.extra.get("builtin_egress")
    return _sha256(_canonical_json_bytes(document))


def validate_route_payload(payload: bytes) -> str:
    """Return one safe relative URL suffix from a committed route file."""

    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > WEB_IMPACT_DRIVER_MAX_ROUTE_BYTES
        or b"\x00" in payload
    ):
        raise WebImpactDriverError("route_payload_invalid")
    try:
        route = payload.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise WebImpactDriverError("route_payload_invalid") from error
    if route.endswith("\n"):
        route = route[:-1]
    if (
        not route.startswith("/")
        or route.startswith("//")
        or any(character in route for character in "\r\n\\")
    ):
        raise WebImpactDriverError("route_payload_invalid")
    parsed = urlsplit(route)
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise WebImpactDriverError("route_payload_invalid")
    return route


def web_impact_trace_contract_sha256(
    *,
    source_kind: str,
    source_pointer_sha256: str,
    sink_kind: str,
    sink_pointer_sha256: str,
    runtime_step_ordinal: int,
) -> str:
    return _sha256(
        _canonical_json_bytes(
            {
                "protocol": WEB_IMPACT_TRACE_CONTRACT_PROTOCOL,
                "runtime_step_ordinal": runtime_step_ordinal,
                "sink_kind": sink_kind,
                "sink_pointer_sha256": sink_pointer_sha256,
                "source_kind": source_kind,
                "source_pointer_sha256": source_pointer_sha256,
            }
        )
    )


__all__ = [
    "WEB_IMPACT_DRIVER_MAX_BYTES",
    "WEB_IMPACT_DRIVER_MAX_ROUTE_BYTES",
    "WEB_IMPACT_DRIVER_PROTOCOL",
    "WEB_IMPACT_DRIVER_SCHEMA_VERSION",
    "WEB_IMPACT_REQUEST_SHAPE_PROTOCOL",
    "WEB_IMPACT_TARGET_BINDING_PROTOCOL",
    "WEB_IMPACT_TRACE_CONTRACT_PROTOCOL",
    "WebImpactDriverError",
    "WebImpactDriverInput",
    "WebImpactDriverManifest",
    "WebImpactDriverStep",
    "parse_web_impact_driver_manifest",
    "validate_route_payload",
    "web_impact_target_binding_sha256",
    "web_impact_trace_contract_sha256",
]
