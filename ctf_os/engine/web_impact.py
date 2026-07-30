"""Deterministic, raw-free Web impact proof contract.

This module does not send requests and does not inspect model prose.  It binds
three value-free identities, one pre-approved target commitment, an ordered
HTTP/browser timeline, source-to-sink trace evidence, and a deterministic
response-artifact oracle to three fresh sandbox replay receipts.  When a
patched/non-vulnerable differential is declared, three equally fresh control
receipts are mandatory as well.

A passing result proves only the declared Web impact oracle.  It never proves
a flag, authorizes a candidate, transitions the challenge to submission-ready,
or submits anything.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from itertools import islice


WEB_IMPACT_PROTOCOL = "ctfos.web.impact.v1"
WEB_IMPACT_SCHEMA_VERSION = 1
WEB_IMPACT_REPLAY_COUNT = 3
WEB_IMPACT_MAX_TIMELINE_STEPS = 32
WEB_IMPACT_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
WEB_IMPACT_MAX_TRACE_BYTES = 8 * 1024 * 1024
WEB_IMPACT_MAX_PLAN_BYTES = 64 * 1024
WEB_IMPACT_MAX_EVALUATION_BYTES = 512 * 1024

WEB_IDENTITY_ROLES = ("admin", "attacker", "user")
WEB_TIMELINE_CHANNELS = frozenset({"browser", "http"})
WEB_SOURCE_SINK_OBSERVATION_AUTHORITY = "declared_commitment_only"
WEB_HTTP_METHODS = frozenset(
    {
        "DELETE",
        "GET",
        "HEAD",
        "OPTIONS",
        "PATCH",
        "POST",
        "PUT",
    }
)
WEB_SOURCE_KINDS = frozenset(
    {
        "database_object",
        "path_segment",
        "request_body",
        "request_header_name",
        "request_parameter",
        "session_role",
    }
)
WEB_SINK_KINDS = frozenset(
    {
        "browser_dom",
        "outbound_request",
        "privileged_action",
        "response_body",
        "state_change",
    }
)
WEB_IMPACT_KINDS = frozenset(
    {
        "authorization_bypass",
        "code_execution",
        "confidentiality",
        "integrity",
        "out_of_band_interaction",
        "privilege_escalation",
    }
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_NON_AUTHORITIES = {
    "automatic_submission_authorized": False,
    "candidate_authorized": False,
    "challenge_proof_satisfied": False,
    "flag_proven": False,
    "self_report_accepted": False,
}


class WebImpactPreflightError(ValueError):
    """The operator/engine supplied an invalid Web impact plan."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class WebImpactVerdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"


def _canonical_json_bytes(
    value: object,
    *,
    maximum_bytes: int | None = None,
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
        raise ValueError("canonical_json_invalid") from error
    if maximum_bytes is not None and len(payload) > maximum_bytes:
        raise ValueError("canonical_json_size_exceeded")
    return payload


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _valid_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _valid_image_digest(value: object) -> bool:
    return type(value) is str and _IMAGE_DIGEST.fullmatch(value) is not None


def _valid_id(value: object) -> bool:
    return type(value) is str and _OPAQUE_ID.fullmatch(value) is not None


def _valid_size(value: object, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _valid_status(value: object) -> bool:
    return type(value) is int and 100 <= value <= 599


@dataclass(frozen=True, slots=True)
class WebArtifactCommitment:
    """Value-free pointer to one immutable request/response/trace artifact."""

    artifact_id: str
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True, slots=True)
class WebIdentityBinding:
    """One role and an opaque engine-owned principal commitment."""

    role: str
    principal_binding_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "principal_binding_sha256": self.principal_binding_sha256,
            "role": self.role,
        }


@dataclass(frozen=True, slots=True)
class WebTimelineStep:
    """One value-free request shape in the required execution order."""

    ordinal: int
    channel: str
    role: str
    method: str
    route_binding_sha256: str
    request_shape_sha256: str
    expected_status: int

    def to_dict(self) -> dict[str, object]:
        return {
            "channel": self.channel,
            "expected_status": self.expected_status,
            "method": self.method,
            "ordinal": self.ordinal,
            "request_shape_sha256": self.request_shape_sha256,
            "role": self.role,
            "route_binding_sha256": self.route_binding_sha256,
        }


@dataclass(frozen=True, slots=True)
class WebSourceSinkContract:
    """Expected static/runtime join, represented only by commitments."""

    source_kind: str
    source_pointer_sha256: str
    sink_kind: str
    sink_pointer_sha256: str
    runtime_step_ordinal: int
    trace_contract_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "runtime_step_ordinal": self.runtime_step_ordinal,
            "sink_kind": self.sink_kind,
            "sink_pointer_sha256": self.sink_pointer_sha256,
            "source_kind": self.source_kind,
            "source_pointer_sha256": self.source_pointer_sha256,
            "trace_contract_sha256": self.trace_contract_sha256,
        }


@dataclass(frozen=True, slots=True)
class WebImpactOracle:
    """Exact vulnerable-target response artifact accepted as impact."""

    impact_kind: str
    sink_step_ordinal: int
    expected_status: int
    expected_response_sha256: str
    expected_response_size_bytes: int

    def content_dict(self) -> dict[str, object]:
        return {
            "expected_response_sha256": self.expected_response_sha256,
            "expected_response_size_bytes": (
                self.expected_response_size_bytes
            ),
            "expected_status": self.expected_status,
            "impact_kind": self.impact_kind,
            "kind": "sink_response_artifact_sha256_equals_v1",
            "sink_step_ordinal": self.sink_step_ordinal,
        }

    @property
    def contract_sha256(self) -> str:
        return _sha256(_canonical_json_bytes(self.content_dict()))

    def to_dict(self) -> dict[str, object]:
        value = self.content_dict()
        value["contract_sha256"] = self.contract_sha256
        return value


@dataclass(frozen=True, slots=True)
class WebDifferentialPolicy:
    """Exact expected result for a patched/non-vulnerable control target."""

    control_target_binding_sha256: str
    control_target_generation: int
    expected_status: int
    expected_response_sha256: str
    expected_response_size_bytes: int

    def content_dict(self) -> dict[str, object]:
        return {
            "control_target_binding_sha256": (
                self.control_target_binding_sha256
            ),
            "control_target_generation": self.control_target_generation,
            "expected_response_sha256": self.expected_response_sha256,
            "expected_response_size_bytes": (
                self.expected_response_size_bytes
            ),
            "expected_status": self.expected_status,
            "kind": "patched_or_non_vulnerable_exact_response_v1",
        }

    @property
    def policy_sha256(self) -> str:
        return _sha256(_canonical_json_bytes(self.content_dict()))

    def to_dict(self) -> dict[str, object]:
        value = self.content_dict()
        value["policy_sha256"] = self.policy_sha256
        return value


@dataclass(frozen=True, slots=True)
class WebImpactPlan:
    """Engine/operator-owned immutable Web impact expectation."""

    source_manifest_sha256: str
    runtime_image_digest: str
    authorized_target_binding_sha256: str
    target_generation: int
    identities: tuple[WebIdentityBinding, ...]
    timeline: tuple[WebTimelineStep, ...]
    source_sink: WebSourceSinkContract
    oracle: WebImpactOracle
    differential: WebDifferentialPolicy | None

    @property
    def identity_binding_sha256(self) -> str:
        return _sha256(
            _canonical_json_bytes(
                [item.to_dict() for item in self.identities]
            )
        )

    def content_dict(self) -> dict[str, object]:
        return {
            "authorized_target": {
                "binding_sha256": self.authorized_target_binding_sha256,
                "generation": self.target_generation,
            },
            "differential": (
                self.differential.to_dict()
                if self.differential is not None
                else None
            ),
            "identities": [
                item.to_dict() for item in self.identities
            ],
            "identity_binding_sha256": self.identity_binding_sha256,
            "oracle": self.oracle.to_dict(),
            "protocol": WEB_IMPACT_PROTOCOL,
            "runtime_image_digest": self.runtime_image_digest,
            "schema_version": WEB_IMPACT_SCHEMA_VERSION,
            "source_manifest_sha256": self.source_manifest_sha256,
            "source_sink": self.source_sink.to_dict(),
            "timeline": [item.to_dict() for item in self.timeline],
        }

    @property
    def plan_sha256(self) -> str:
        return _sha256(
            _canonical_json_bytes(
                self.content_dict(),
                maximum_bytes=WEB_IMPACT_MAX_PLAN_BYTES,
            )
        )

    def to_dict(self) -> dict[str, object]:
        value = self.content_dict()
        value["plan_sha256"] = self.plan_sha256
        return value

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(
            self.to_dict(),
            maximum_bytes=WEB_IMPACT_MAX_PLAN_BYTES,
        )


def _validate_artifact(
    value: object,
    *,
    maximum_bytes: int = WEB_IMPACT_MAX_ARTIFACT_BYTES,
) -> bool:
    return (
        type(value) is WebArtifactCommitment
        and _valid_id(value.artifact_id)
        and _valid_sha256(value.sha256)
        and _valid_size(value.size_bytes, maximum_bytes)
    )


def build_web_impact_plan(
    *,
    source_manifest_sha256: str,
    runtime_image_digest: str,
    authorized_target_binding_sha256: str,
    target_generation: int,
    identities: Iterable[WebIdentityBinding],
    timeline: Iterable[WebTimelineStep],
    source_sink: WebSourceSinkContract,
    oracle: WebImpactOracle,
    differential: WebDifferentialPolicy | None = None,
) -> WebImpactPlan:
    """Build the only canonical plan accepted by the replay evaluator."""

    if not _valid_sha256(source_manifest_sha256):
        raise WebImpactPreflightError("source_manifest_invalid")
    if not _valid_image_digest(runtime_image_digest):
        raise WebImpactPreflightError("runtime_image_not_digest_pinned")
    if not _valid_sha256(authorized_target_binding_sha256):
        raise WebImpactPreflightError("target_binding_invalid")
    if not _valid_size(target_generation, 2**63 - 1):
        raise WebImpactPreflightError("target_generation_invalid")
    try:
        identity_values = tuple(
            islice(iter(identities), len(WEB_IDENTITY_ROLES) + 1)
        )
    except Exception as error:
        raise WebImpactPreflightError(
            "identity_bindings_invalid"
        ) from error
    if (
        len(identity_values) != len(WEB_IDENTITY_ROLES)
        or any(type(item) is not WebIdentityBinding for item in identity_values)
        or tuple(item.role for item in identity_values) != WEB_IDENTITY_ROLES
        or any(
            not _valid_sha256(item.principal_binding_sha256)
            for item in identity_values
        )
        or len(
            {
                item.principal_binding_sha256
                for item in identity_values
            }
        )
        != len(identity_values)
    ):
        raise WebImpactPreflightError("identity_bindings_invalid")
    try:
        timeline_values = tuple(
            islice(iter(timeline), WEB_IMPACT_MAX_TIMELINE_STEPS + 1)
        )
    except Exception as error:
        raise WebImpactPreflightError("timeline_invalid") from error
    if (
        not 2 <= len(timeline_values) <= WEB_IMPACT_MAX_TIMELINE_STEPS
        or any(type(item) is not WebTimelineStep for item in timeline_values)
        or any(type(item.ordinal) is not int for item in timeline_values)
        or tuple(item.ordinal for item in timeline_values)
        != tuple(range(1, len(timeline_values) + 1))
        or {item.channel for item in timeline_values}
        != WEB_TIMELINE_CHANNELS
        or any(
            item.role not in WEB_IDENTITY_ROLES
            or item.method not in WEB_HTTP_METHODS
            or not _valid_sha256(item.route_binding_sha256)
            or not _valid_sha256(item.request_shape_sha256)
            or not _valid_status(item.expected_status)
            for item in timeline_values
        )
    ):
        raise WebImpactPreflightError("timeline_invalid")
    if (
        type(source_sink) is not WebSourceSinkContract
        or source_sink.source_kind not in WEB_SOURCE_KINDS
        or source_sink.sink_kind not in WEB_SINK_KINDS
        or not _valid_sha256(source_sink.source_pointer_sha256)
        or not _valid_sha256(source_sink.sink_pointer_sha256)
        or not _valid_sha256(source_sink.trace_contract_sha256)
        or type(source_sink.runtime_step_ordinal) is not int
        or not 1
        <= source_sink.runtime_step_ordinal
        <= len(timeline_values)
    ):
        raise WebImpactPreflightError("source_sink_contract_invalid")
    if (
        type(oracle) is not WebImpactOracle
        or oracle.impact_kind not in WEB_IMPACT_KINDS
        or type(oracle.sink_step_ordinal) is not int
        or not 1 <= oracle.sink_step_ordinal <= len(timeline_values)
        or oracle.sink_step_ordinal
        != source_sink.runtime_step_ordinal
        or not _valid_status(oracle.expected_status)
        or oracle.expected_status
        != timeline_values[oracle.sink_step_ordinal - 1].expected_status
        or not _valid_sha256(oracle.expected_response_sha256)
        or not _valid_size(
            oracle.expected_response_size_bytes,
            WEB_IMPACT_MAX_ARTIFACT_BYTES,
        )
    ):
        raise WebImpactPreflightError("impact_oracle_invalid")
    if differential is not None:
        if (
            type(differential) is not WebDifferentialPolicy
            or not _valid_sha256(
                differential.control_target_binding_sha256
            )
            or differential.control_target_binding_sha256
            == authorized_target_binding_sha256
            or not _valid_size(
                differential.control_target_generation,
                2**63 - 1,
            )
            or not _valid_status(differential.expected_status)
            or not _valid_sha256(
                differential.expected_response_sha256
            )
            or not _valid_size(
                differential.expected_response_size_bytes,
                WEB_IMPACT_MAX_ARTIFACT_BYTES,
            )
            or (
                differential.expected_response_sha256,
                differential.expected_response_size_bytes,
                differential.expected_status,
            )
            == (
                oracle.expected_response_sha256,
                oracle.expected_response_size_bytes,
                oracle.expected_status,
            )
        ):
            raise WebImpactPreflightError(
                "differential_policy_invalid"
            )
    plan = WebImpactPlan(
        source_manifest_sha256=source_manifest_sha256,
        runtime_image_digest=runtime_image_digest,
        authorized_target_binding_sha256=(
            authorized_target_binding_sha256
        ),
        target_generation=target_generation,
        identities=identity_values,
        timeline=timeline_values,
        source_sink=source_sink,
        oracle=oracle,
        differential=differential,
    )
    try:
        plan.canonical_bytes
    except ValueError as error:
        raise WebImpactPreflightError("plan_size_exceeded") from error
    return plan


def web_identity_epoch_sha256(
    plan: WebImpactPlan,
    replay_nonce_sha256: str,
) -> str:
    """Derive a value-free binding for three fresh role-specific jars."""

    if type(plan) is not WebImpactPlan:
        raise TypeError("plan must be an exact WebImpactPlan")
    if not _valid_sha256(replay_nonce_sha256):
        raise ValueError("replay_nonce_sha256 is invalid")
    return _sha256(
        _canonical_json_bytes(
            {
                "identity_binding_sha256": (
                    plan.identity_binding_sha256
                ),
                "replay_nonce_sha256": replay_nonce_sha256,
                "roles": list(WEB_IDENTITY_ROLES),
            }
        )
    )


def web_replay_execution_contract_sha256(
    plan: WebImpactPlan,
    *,
    target_kind: str,
    replay_ordinal: int,
    replay_nonce_sha256: str,
) -> str:
    """Derive the engine-owned sandbox contract for one replay receipt."""

    if type(plan) is not WebImpactPlan or not _plan_is_canonical(plan):
        raise TypeError("plan must be one canonical WebImpactPlan")
    if target_kind not in {"vulnerable", "control"}:
        raise ValueError("target_kind is invalid")
    if target_kind == "control" and plan.differential is None:
        raise ValueError("control target is not declared")
    if (
        type(replay_ordinal) is not int
        or not 1 <= replay_ordinal <= WEB_IMPACT_REPLAY_COUNT
        or not _valid_sha256(replay_nonce_sha256)
    ):
        raise ValueError("replay binding is invalid")
    control = target_kind == "control"
    target_binding = (
        plan.differential.control_target_binding_sha256
        if control and plan.differential is not None
        else plan.authorized_target_binding_sha256
    )
    target_generation = (
        plan.differential.control_target_generation
        if control and plan.differential is not None
        else plan.target_generation
    )
    return _sha256(
        _canonical_json_bytes(
            {
                "capture_policy": {
                    "complete": True,
                    "truncation_known": True,
                    "truncated": False,
                },
                "fresh_identity_state": True,
                "identity_epoch_sha256": web_identity_epoch_sha256(
                    plan,
                    replay_nonce_sha256,
                ),
                "network_policy": "preapproved_target_only",
                "plan_sha256": plan.plan_sha256,
                "replay_nonce_sha256": replay_nonce_sha256,
                "replay_ordinal": replay_ordinal,
                "runtime_image_digest": plan.runtime_image_digest,
                "target_binding_sha256": target_binding,
                "target_generation": target_generation,
                "target_kind": target_kind,
                "workspace_policy": "fresh",
            }
        )
    )


@dataclass(frozen=True, slots=True)
class WebTimelineEvent:
    ordinal: int
    channel: str
    role: str
    method: str
    route_binding_sha256: str
    request_shape_sha256: str
    status: int
    request_artifact: WebArtifactCommitment
    response_artifact: WebArtifactCommitment
    cookie_transition_sha256: str
    security_context_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "channel": self.channel,
            "cookie_transition_sha256": self.cookie_transition_sha256,
            "method": self.method,
            "ordinal": self.ordinal,
            "request_artifact": self.request_artifact.to_dict(),
            "request_shape_sha256": self.request_shape_sha256,
            "response_artifact": self.response_artifact.to_dict(),
            "role": self.role,
            "route_binding_sha256": self.route_binding_sha256,
            "security_context_sha256": self.security_context_sha256,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class WebSourceSinkObservation:
    source_kind: str
    source_pointer_sha256: str
    sink_kind: str
    sink_pointer_sha256: str
    runtime_step_ordinal: int
    runtime_request_sha256: str
    trace_contract_sha256: str
    trace_artifact: WebArtifactCommitment
    reached_sink: bool
    observation_authority: str = (
        WEB_SOURCE_SINK_OBSERVATION_AUTHORITY
    )
    observer_attestation_sha256: str | None = None
    source_sink_observed: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "observation_authority": self.observation_authority,
            "observer_attestation_sha256": (
                self.observer_attestation_sha256
            ),
            "reached_sink": self.reached_sink,
            "runtime_request_sha256": self.runtime_request_sha256,
            "runtime_step_ordinal": self.runtime_step_ordinal,
            "sink_kind": self.sink_kind,
            "sink_pointer_sha256": self.sink_pointer_sha256,
            "source_kind": self.source_kind,
            "source_pointer_sha256": self.source_pointer_sha256,
            "source_sink_observed": self.source_sink_observed,
            "trace_artifact": self.trace_artifact.to_dict(),
            "trace_contract_sha256": self.trace_contract_sha256,
        }


@dataclass(frozen=True, slots=True)
class WebImpactReplayObservation:
    """Engine-derived receipt for one clean vulnerable or control replay."""

    target_kind: str
    replay_ordinal: int
    run_id: str
    receipt_id: str
    receipt_sha256: str
    replay_nonce_sha256: str
    identity_epoch_sha256: str
    execution_contract_sha256: str
    plan_sha256: str
    source_manifest_sha256: str
    runtime_image_digest: str
    authorized_target_binding_sha256: str
    target_generation: int
    clean_workspace: bool
    fresh_identity_state: bool
    network_target_authorized: bool
    orchestration_status: str
    exit_code: int | None
    timed_out: bool
    capture_complete: bool
    truncation_known: bool
    truncated: bool | None
    capture_error: str | None
    timeline: tuple[WebTimelineEvent, ...]
    source_sink: WebSourceSinkObservation


@dataclass(frozen=True, slots=True)
class WebImpactReplayRecord:
    target_kind: str
    replay_ordinal: int
    run_id: str
    receipt_id: str
    receipt_sha256: str
    replay_nonce_sha256: str
    identity_epoch_sha256: str
    execution_contract_sha256: str
    plan_sha256: str
    source_manifest_sha256: str
    runtime_image_digest: str
    authorized_target_binding_sha256: str
    target_generation: int
    timeline: tuple[WebTimelineEvent, ...]
    source_sink: WebSourceSinkObservation

    def to_dict(self) -> dict[str, object]:
        return {
            "authorized_target_binding_sha256": (
                self.authorized_target_binding_sha256
            ),
            "identity_epoch_sha256": self.identity_epoch_sha256,
            "execution_contract_sha256": (
                self.execution_contract_sha256
            ),
            "plan_sha256": self.plan_sha256,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "replay_nonce_sha256": self.replay_nonce_sha256,
            "replay_ordinal": self.replay_ordinal,
            "run_id": self.run_id,
            "runtime_image_digest": self.runtime_image_digest,
            "source_manifest_sha256": self.source_manifest_sha256,
            "source_sink": self.source_sink.to_dict(),
            "target_generation": self.target_generation,
            "target_kind": self.target_kind,
            "timeline": [item.to_dict() for item in self.timeline],
            "transport": {
                "capture_complete": True,
                "clean_workspace": True,
                "exit_code": 0,
                "fresh_identity_state": True,
                "network_target_authorized": True,
                "orchestration_status": "completed",
                "timed_out": False,
                "truncated": False,
                "truncation_known": True,
            },
        }


@dataclass(frozen=True, slots=True)
class WebImpactEvaluation:
    plan: WebImpactPlan | None
    replay_records: tuple[WebImpactReplayRecord, ...]
    failure_codes: tuple[str, ...]
    verdict: WebImpactVerdict

    @property
    def passed(self) -> bool:
        expected = (
            WEB_IMPACT_REPLAY_COUNT
            * (2 if self.plan is not None and self.plan.differential else 1)
        )
        return (
            self.verdict is WebImpactVerdict.CONFIRMED
            and self.plan is not None
            and not self.failure_codes
            and len(self.replay_records) == expected
        )

    @property
    def runtime_request_response_differential_confirmed(self) -> bool:
        return (
            self.passed
            and self.plan is not None
            and self.plan.differential is not None
        )

    @property
    def source_sink_observed(self) -> bool:
        # The current HTTP/browser helpers observe requests, responses, and
        # cookie transitions.  They do not carry an image-owned source/sink
        # observer attestation, so declared pointer commitments cannot acquire
        # runtime data-flow authority.
        return False

    def to_dict(self) -> dict[str, object]:
        return {
            "authorities": {
                **_NON_AUTHORITIES,
                "executed_web_impact_fact_authorized": self.passed,
                "progress_marker_authorized": self.passed,
                "runtime_request_response_differential_confirmed": (
                    self.runtime_request_response_differential_confirmed
                ),
                "source_sink_observed": self.source_sink_observed,
                "web_impact_oracle_satisfied": self.passed,
            },
            "failure_codes": list(self.failure_codes),
            "passed": self.passed,
            "plan": self.plan.to_dict() if self.plan is not None else None,
            "plan_sha256": (
                self.plan.plan_sha256
                if self.plan is not None
                else None
            ),
            "protocol": WEB_IMPACT_PROTOCOL,
            "replay_records": [
                item.to_dict() for item in self.replay_records
            ],
            "schema_version": WEB_IMPACT_SCHEMA_VERSION,
            "source_sink_observed": self.source_sink_observed,
            "runtime_request_response_differential_confirmed": (
                self.runtime_request_response_differential_confirmed
            ),
            "verdict": self.verdict.value,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(
            self.to_dict(),
            maximum_bytes=WEB_IMPACT_MAX_EVALUATION_BYTES,
        )

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)

    def reduction_projection(self) -> dict[str, object]:
        if not self.passed:
            return {
                "automatic_submission": False,
                "candidate": None,
                "executed_fact": None,
                "progress": None,
                "proof": None,
            }
        assert self.plan is not None
        last = self.replay_records[WEB_IMPACT_REPLAY_COUNT - 1]
        sink_event = last.timeline[
            self.plan.oracle.sink_step_ordinal - 1
        ]
        binding = {
            "evaluation_sha256": self.sha256,
            "oracle_contract_sha256": (
                self.plan.oracle.contract_sha256
            ),
            "plan_sha256": self.plan.plan_sha256,
            "response_artifact_sha256": (
                sink_event.response_artifact.sha256
            ),
            "runtime_request_response_differential_confirmed": (
                self.runtime_request_response_differential_confirmed
            ),
            "source_sink_observed": self.source_sink_observed,
        }
        return {
            "automatic_submission": False,
            "candidate": None,
            "executed_fact": {
                "artifact_id": sink_event.response_artifact.artifact_id,
                "extra": {"web_impact": binding},
                "provenance": "executed",
                "source_run_id": last.run_id,
                "statement": (
                    "Three fresh sandbox replays satisfied the explicit "
                    f"{self.plan.oracle.impact_kind} HTTP response oracle"
                    + (
                        " and three patched/non-vulnerable controls "
                        "confirmed a runtime request/response differential. "
                        "Declared source/sink commitments were not "
                        "runtime-observed."
                        if self.plan.differential is not None
                        else "; declared source/sink commitments were not "
                        "runtime-observed."
                    )
                ),
            },
            "progress": {
                "artifact_ids": [
                    sink_event.response_artifact.artifact_id,
                    last.source_sink.trace_artifact.artifact_id,
                ],
                "extra": {"web_impact": binding},
                "run_id": last.run_id,
                "statement": (
                    "Deterministic Web response oracle reproduced in three "
                    "fresh identity-isolated executions; source/sink "
                    "observation authority remains false"
                ),
            },
            "proof": None,
        }


def _plan_is_canonical(plan: WebImpactPlan) -> bool:
    try:
        rebuilt = build_web_impact_plan(
            source_manifest_sha256=plan.source_manifest_sha256,
            runtime_image_digest=plan.runtime_image_digest,
            authorized_target_binding_sha256=(
                plan.authorized_target_binding_sha256
            ),
            target_generation=plan.target_generation,
            identities=plan.identities,
            timeline=plan.timeline,
            source_sink=plan.source_sink,
            oracle=plan.oracle,
            differential=plan.differential,
        )
        return rebuilt == plan
    except (AttributeError, WebImpactPreflightError, ValueError):
        return False


def _failure(code: str, position: int | None = None) -> str:
    return code if position is None else f"replay-{position}:{code}"


def _timeline_valid(
    plan: WebImpactPlan,
    observation: WebImpactReplayObservation,
    *,
    control: bool,
    used_artifact_ids: set[str],
) -> bool:
    if (
        type(observation.timeline) is not tuple
        or len(observation.timeline) != len(plan.timeline)
    ):
        return False
    sink_ordinal = plan.oracle.sink_step_ordinal
    for step, event in zip(
        plan.timeline,
        observation.timeline,
        strict=True,
    ):
        expected_status = (
            plan.differential.expected_status
            if control
            and plan.differential is not None
            and step.ordinal == sink_ordinal
            else step.expected_status
        )
        if (
            type(event) is not WebTimelineEvent
            or type(event.ordinal) is not int
            or event.ordinal != step.ordinal
            or event.channel != step.channel
            or event.role != step.role
            or event.method != step.method
            or event.route_binding_sha256
            != step.route_binding_sha256
            or event.request_shape_sha256
            != step.request_shape_sha256
            or event.status != expected_status
            or not _valid_sha256(event.cookie_transition_sha256)
            or not _valid_sha256(event.security_context_sha256)
            or not _validate_artifact(event.request_artifact)
            or not _validate_artifact(event.response_artifact)
            or event.request_artifact.artifact_id
            == event.response_artifact.artifact_id
        ):
            return False
        for artifact in (
            event.request_artifact,
            event.response_artifact,
        ):
            if artifact.artifact_id in used_artifact_ids:
                return False
            used_artifact_ids.add(artifact.artifact_id)
    return True


def _source_sink_valid(
    plan: WebImpactPlan,
    observation: WebImpactReplayObservation,
    *,
    control: bool,
    used_artifact_ids: set[str],
) -> bool:
    value = observation.source_sink
    if type(value) is not WebSourceSinkObservation:
        return False
    expected = plan.source_sink
    runtime_event = observation.timeline[
        expected.runtime_step_ordinal - 1
    ]
    if (
        type(value.reached_sink) is not bool
        or value.observation_authority
        != WEB_SOURCE_SINK_OBSERVATION_AUTHORITY
        or value.observer_attestation_sha256 is not None
        or value.source_sink_observed is not False
        or type(value.runtime_step_ordinal) is not int
        or value.source_kind != expected.source_kind
        or value.source_pointer_sha256
        != expected.source_pointer_sha256
        or value.sink_kind != expected.sink_kind
        or value.sink_pointer_sha256 != expected.sink_pointer_sha256
        or value.runtime_step_ordinal
        != expected.runtime_step_ordinal
        or value.trace_contract_sha256
        != expected.trace_contract_sha256
        or value.runtime_request_sha256
        != runtime_event.request_artifact.sha256
        or value.reached_sink is not (not control)
        or not _validate_artifact(
            value.trace_artifact,
            maximum_bytes=WEB_IMPACT_MAX_TRACE_BYTES,
        )
        or value.trace_artifact.artifact_id in used_artifact_ids
    ):
        return False
    used_artifact_ids.add(value.trace_artifact.artifact_id)
    return True


def _oracle_valid(
    plan: WebImpactPlan,
    observation: WebImpactReplayObservation,
    *,
    control: bool,
) -> bool:
    if (
        type(observation.timeline) is not tuple
        or len(observation.timeline) != len(plan.timeline)
        or any(
            type(item) is not WebTimelineEvent
            for item in observation.timeline
        )
    ):
        return False
    response = observation.timeline[
        plan.oracle.sink_step_ordinal - 1
    ].response_artifact
    if control:
        policy = plan.differential
        return (
            policy is not None
            and response.sha256 == policy.expected_response_sha256
            and response.size_bytes
            == policy.expected_response_size_bytes
        )
    return (
        response.sha256 == plan.oracle.expected_response_sha256
        and response.size_bytes
        == plan.oracle.expected_response_size_bytes
    )


def evaluate_web_impact(
    plan: WebImpactPlan,
    observations: Iterable[WebImpactReplayObservation],
) -> WebImpactEvaluation:
    """Evaluate three vulnerable replays and optional three controls."""

    if type(plan) is not WebImpactPlan or not _plan_is_canonical(plan):
        return WebImpactEvaluation(
            plan=None,
            replay_records=(),
            failure_codes=("plan_invalid",),
            verdict=WebImpactVerdict.REJECTED,
        )
    expected_count = WEB_IMPACT_REPLAY_COUNT * (
        2 if plan.differential is not None else 1
    )
    try:
        values = tuple(
            islice(iter(observations), expected_count + 1)
        )
    except Exception:
        return WebImpactEvaluation(
            plan=plan,
            replay_records=(),
            failure_codes=("observations_not_iterable",),
            verdict=WebImpactVerdict.REJECTED,
        )
    failures: list[str] = []
    if len(values) != expected_count:
        failures.append("replay_count_mismatch")
    retained = values[:expected_count]
    used_runs: set[str] = set()
    used_receipts: set[str] = set()
    used_receipt_hashes: set[str] = set()
    used_nonces: set[str] = set()
    used_artifact_ids: set[str] = set()
    records: list[WebImpactReplayRecord] = []
    for position, raw in enumerate(retained, start=1):
        if type(raw) is not WebImpactReplayObservation:
            failures.append(_failure("observation_type_invalid", position))
            continue
        control = position > WEB_IMPACT_REPLAY_COUNT
        expected_kind = "control" if control else "vulnerable"
        expected_ordinal = (
            position - WEB_IMPACT_REPLAY_COUNT
            if control
            else position
        )
        target_binding = (
            plan.differential.control_target_binding_sha256
            if control and plan.differential is not None
            else plan.authorized_target_binding_sha256
        )
        target_generation = (
            plan.differential.control_target_generation
            if control and plan.differential is not None
            else plan.target_generation
        )
        before = len(failures)
        if (
            raw.target_kind != expected_kind
            or raw.replay_ordinal != expected_ordinal
        ):
            failures.append(_failure("replay_order_mismatch", position))
        if not _valid_id(raw.run_id) or raw.run_id in used_runs:
            failures.append(_failure("run_id_invalid_or_reused", position))
        else:
            used_runs.add(raw.run_id)
        if (
            not _valid_id(raw.receipt_id)
            or raw.receipt_id in used_receipts
        ):
            failures.append(
                _failure("receipt_id_invalid_or_reused", position)
            )
        else:
            used_receipts.add(raw.receipt_id)
        if (
            not _valid_sha256(raw.receipt_sha256)
            or raw.receipt_sha256 in used_receipt_hashes
        ):
            failures.append(
                _failure("receipt_hash_invalid_or_reused", position)
            )
        else:
            used_receipt_hashes.add(raw.receipt_sha256)
        if (
            not _valid_sha256(raw.replay_nonce_sha256)
            or raw.replay_nonce_sha256 in used_nonces
        ):
            failures.append(
                _failure("freshness_nonce_invalid_or_reused", position)
            )
        else:
            used_nonces.add(raw.replay_nonce_sha256)
        expected_epoch = (
            web_identity_epoch_sha256(
                plan,
                raw.replay_nonce_sha256,
            )
            if _valid_sha256(raw.replay_nonce_sha256)
            else None
        )
        expected_execution_contract = (
            web_replay_execution_contract_sha256(
                plan,
                target_kind=expected_kind,
                replay_ordinal=expected_ordinal,
                replay_nonce_sha256=raw.replay_nonce_sha256,
            )
            if _valid_sha256(raw.replay_nonce_sha256)
            else None
        )
        if (
            type(raw.replay_ordinal) is not int
            or raw.identity_epoch_sha256 != expected_epoch
            or raw.execution_contract_sha256
            != expected_execution_contract
            or raw.plan_sha256 != plan.plan_sha256
            or raw.source_manifest_sha256
            != plan.source_manifest_sha256
            or raw.runtime_image_digest != plan.runtime_image_digest
            or raw.authorized_target_binding_sha256 != target_binding
            or type(raw.target_generation) is not int
            or raw.target_generation != target_generation
        ):
            failures.append(_failure("execution_binding_mismatch", position))
        if (
            raw.clean_workspace is not True
            or raw.fresh_identity_state is not True
            or raw.network_target_authorized is not True
            or raw.orchestration_status != "completed"
            or type(raw.exit_code) is not int
            or raw.exit_code != 0
            or raw.timed_out is not False
            or raw.capture_complete is not True
            or raw.truncation_known is not True
            or raw.truncated is not False
            or raw.capture_error is not None
        ):
            failures.append(_failure("transport_invalid", position))
        timeline_valid = _timeline_valid(
            plan,
            raw,
            control=control,
            used_artifact_ids=used_artifact_ids,
        )
        if not timeline_valid:
            failures.append(_failure("timeline_invalid", position))
        elif not _source_sink_valid(
            plan,
            raw,
            control=control,
            used_artifact_ids=used_artifact_ids,
        ):
            failures.append(
                _failure("source_sink_evidence_invalid", position)
            )
        # A structurally valid replay remains durable evidence even when its
        # response fails the impact oracle.  Retaining it prevents callers
        # from cherry-picking only successful replays while the failure code
        # continues to make the aggregate verdict fail closed.
        recordable = len(failures) == before
        if timeline_valid and not _oracle_valid(
            plan,
            raw,
            control=control,
        ):
            failures.append(_failure("impact_oracle_failed", position))
        if recordable:
            records.append(
                WebImpactReplayRecord(
                    target_kind=raw.target_kind,
                    replay_ordinal=raw.replay_ordinal,
                    run_id=raw.run_id,
                    receipt_id=raw.receipt_id,
                    receipt_sha256=raw.receipt_sha256,
                    replay_nonce_sha256=raw.replay_nonce_sha256,
                    identity_epoch_sha256=raw.identity_epoch_sha256,
                    execution_contract_sha256=(
                        raw.execution_contract_sha256
                    ),
                    plan_sha256=raw.plan_sha256,
                    source_manifest_sha256=(
                        raw.source_manifest_sha256
                    ),
                    runtime_image_digest=raw.runtime_image_digest,
                    authorized_target_binding_sha256=(
                        raw.authorized_target_binding_sha256
                    ),
                    target_generation=raw.target_generation,
                    timeline=raw.timeline,
                    source_sink=raw.source_sink,
                )
            )
    passed = not failures and len(records) == expected_count
    evaluation = WebImpactEvaluation(
        plan=plan,
        replay_records=tuple(records),
        failure_codes=tuple(failures),
        verdict=(
            WebImpactVerdict.CONFIRMED
            if passed
            else WebImpactVerdict.REJECTED
        ),
    )
    try:
        evaluation.canonical_bytes
    except ValueError:
        return WebImpactEvaluation(
            plan=plan,
            replay_records=(),
            failure_codes=("evaluation_size_exceeded",),
            verdict=WebImpactVerdict.REJECTED,
        )
    return evaluation


__all__ = [
    "WEB_IDENTITY_ROLES",
    "WEB_IMPACT_PROTOCOL",
    "WEB_IMPACT_REPLAY_COUNT",
    "WEB_SOURCE_SINK_OBSERVATION_AUTHORITY",
    "WebArtifactCommitment",
    "WebDifferentialPolicy",
    "WebIdentityBinding",
    "WebImpactEvaluation",
    "WebImpactOracle",
    "WebImpactPlan",
    "WebImpactPreflightError",
    "WebImpactReplayObservation",
    "WebImpactReplayRecord",
    "WebImpactVerdict",
    "WebSourceSinkContract",
    "WebSourceSinkObservation",
    "WebTimelineEvent",
    "WebTimelineStep",
    "build_web_impact_plan",
    "evaluate_web_impact",
    "web_identity_epoch_sha256",
    "web_replay_execution_contract_sha256",
]
