"""Pre-issued, transport-bound execution contract for Web impact evidence.

``ctf_os.engine.web_impact`` owns the semantic oracle.  This module deliberately
does not duplicate that oracle.  It adds the missing trust boundary around it:

* a strict, bounded, value-free operator specification;
* an exact comparison with the currently approved target generation;
* three engine-issued vulnerable replay requests and, when requested, three
  engine-issued patched/non-vulnerable control requests;
* immutable nonce, run, request, identity-epoch, and execution commitments
  created before any replay observation exists;
* independently hashed request/response/trace payloads and a canonical
  value-free receipt; and
* a final delegation to :func:`evaluate_web_impact`.

Raw HTTP bodies, cookies, session tokens, and trace bytes are accepted only as
bounded in-memory payloads for hashing.  They are never serialized by any
object in this module.  A confirmed result can authorize one executed Web
impact fact and one progress marker, but never a flag, candidate, challenge
proof, status transition, or automatic submission.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from itertools import islice

from ctf_os.engine.web_impact import (
    WEB_IDENTITY_ROLES,
    WEB_IMPACT_MAX_ARTIFACT_BYTES,
    WEB_IMPACT_MAX_TIMELINE_STEPS,
    WEB_IMPACT_MAX_TRACE_BYTES,
    WEB_IMPACT_REPLAY_COUNT,
    WebArtifactCommitment,
    WebDifferentialPolicy,
    WebIdentityBinding,
    WebImpactEvaluation,
    WebImpactOracle,
    WebImpactPlan,
    WebImpactPreflightError,
    WebImpactReplayObservation,
    WebImpactVerdict,
    WebSourceSinkContract,
    WebSourceSinkObservation,
    WebTimelineEvent,
    WebTimelineStep,
    build_web_impact_plan,
    evaluate_web_impact,
    web_identity_epoch_sha256,
    web_replay_execution_contract_sha256,
)
from ctf_os.store.atomic import StrictJSONError, strict_json_loads


WEB_IMPACT_OPERATOR_SPEC_PROTOCOL = "ctfos.web.impact.operator.v1"
WEB_IMPACT_EXECUTION_PROTOCOL = "ctfos.web.impact.execution.v1"
WEB_IMPACT_EXECUTION_SCHEMA_VERSION = 1
WEB_IMPACT_ALLOWLISTED_TARGET_KIND = "allowlisted_http_origin_v1"

WEB_IMPACT_OPERATOR_SPEC_MAX_BYTES = 64 * 1024
WEB_IMPACT_EXECUTION_REQUEST_MAX_BYTES = 128 * 1024
WEB_IMPACT_EXECUTION_RECEIPT_MAX_BYTES = 128 * 1024
WEB_IMPACT_EXECUTION_PLAN_MAX_BYTES = 512 * 1024
WEB_IMPACT_EXECUTION_EVALUATION_MAX_BYTES = 1024 * 1024
WEB_IMPACT_EXECUTION_MAX_CAPTURE_BYTES = 256 * 1024 * 1024
WEB_IMPACT_REPLAY_NONCE_MIN_BYTES = 16
WEB_IMPACT_REPLAY_NONCE_MAX_BYTES = 64

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,255}$")
_REPLAY_TARGET_KINDS = ("vulnerable", "control")
_RECEIPT_STATUSES = frozenset({"completed", "failed", "interrupted"})
_CAPTURE_ERROR_CODES = frozenset(
    {
        "capture_error",
        "interrupted",
        "sandbox_error",
        "timeout",
    }
)
_NON_AUTHORITIES = {
    "automatic_submission_authorized": False,
    "candidate_authorized": False,
    "challenge_proof_satisfied": False,
    "flag_proven": False,
    "self_report_accepted": False,
}

_OPERATOR_SPEC_KEYS = frozenset(
    {
        "authorized_target",
        "differential",
        "identities",
        "oracle",
        "protocol",
        "runtime_image_digest",
        "schema_version",
        "source_manifest_sha256",
        "source_sink",
        "timeline",
    }
)
_TARGET_KEYS = frozenset({"binding_sha256", "generation", "kind"})
_IDENTITY_KEYS = frozenset({"principal_binding_sha256", "role"})
_TIMELINE_KEYS = frozenset(
    {
        "channel",
        "expected_status",
        "method",
        "ordinal",
        "request_shape_sha256",
        "role",
        "route_binding_sha256",
    }
)
_SOURCE_SINK_KEYS = frozenset(
    {
        "runtime_step_ordinal",
        "sink_kind",
        "sink_pointer_sha256",
        "source_kind",
        "source_pointer_sha256",
        "trace_contract_sha256",
    }
)
_ORACLE_KEYS = frozenset(
    {
        "expected_response_sha256",
        "expected_response_size_bytes",
        "expected_status",
        "impact_kind",
        "sink_step_ordinal",
    }
)
_DIFFERENTIAL_KEYS = frozenset(
    {
        "expected_response_sha256",
        "expected_response_size_bytes",
        "expected_status",
        "target",
    }
)
_RECEIPT_KEYS = frozenset(
    {
        "artifact_manifest_sha256",
        "capture",
        "identity_epoch_sha256",
        "observation_commitment_sha256",
        "operator_spec_sha256",
        "plan_sha256",
        "protocol",
        "receipt_id",
        "replay_nonce_sha256",
        "replay_ordinal",
        "replay_target_kind",
        "request_id",
        "request_sha256",
        "run_id",
        "schema_version",
        "semantic_execution_contract_sha256",
        "target",
        "transport",
        "transport_execution_contract_sha256",
    }
)
_RECEIPT_CAPTURE_KEYS = frozenset(
    {
        "capture_complete",
        "capture_error_code",
        "truncated",
        "truncation_known",
    }
)
_RECEIPT_TRANSPORT_KEYS = frozenset(
    {
        "clean_workspace",
        "exit_code",
        "fresh_identity_state",
        "network_target_authorized",
        "orchestration_status",
        "timed_out",
    }
)


class WebImpactExecutionPreflightError(ValueError):
    """An operator specification or pre-issued replay plan is invalid."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class WebImpactExecutionVerdict(str, Enum):
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


def _valid_generation(value: object) -> bool:
    return type(value) is int and 0 <= value <= (2**63 - 1)


def _exact_dict(
    value: object,
    keys: frozenset[str],
    code: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise WebImpactExecutionPreflightError(code)
    return value


def _bounded_tuple(
    values: Iterable[object],
    *,
    expected: int,
    code: str,
) -> tuple[object, ...]:
    try:
        selected = tuple(islice(iter(values), expected + 1))
    except Exception as error:
        raise WebImpactExecutionPreflightError(code) from error
    if len(selected) != expected:
        raise WebImpactExecutionPreflightError(code)
    return selected


@dataclass(frozen=True, slots=True)
class WebImpactApprovedTarget:
    """Value-free commitment to one currently allowlisted HTTP origin."""

    kind: str
    binding_sha256: str
    generation: int

    def __post_init__(self) -> None:
        if (
            self.kind != WEB_IMPACT_ALLOWLISTED_TARGET_KIND
            or not _valid_sha256(self.binding_sha256)
            or not _valid_generation(self.generation)
        ):
            raise ValueError("approved_target_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "binding_sha256": self.binding_sha256,
            "generation": self.generation,
            "kind": self.kind,
        }


@dataclass(frozen=True, slots=True)
class WebImpactExecutionSpecification:
    """Frozen operator intent after comparison with current engine state."""

    plan: WebImpactPlan
    operator_spec_sha256: str
    operator_spec_size_bytes: int
    vulnerable_target: WebImpactApprovedTarget
    control_target: WebImpactApprovedTarget | None

    def to_dict(self) -> dict[str, object]:
        return {
            "control_target": (
                self.control_target.to_dict()
                if self.control_target is not None
                else None
            ),
            "operator_spec": {
                "sha256": self.operator_spec_sha256,
                "size_bytes": self.operator_spec_size_bytes,
            },
            "plan": self.plan.to_dict(),
            "protocol": WEB_IMPACT_EXECUTION_PROTOCOL,
            "schema_version": WEB_IMPACT_EXECUTION_SCHEMA_VERSION,
            "vulnerable_target": self.vulnerable_target.to_dict(),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(
            self.to_dict(),
            maximum_bytes=WEB_IMPACT_EXECUTION_PLAN_MAX_BYTES,
        )

    @property
    def specification_sha256(self) -> str:
        return _sha256(self.canonical_bytes)


def _parse_target(
    raw: object,
    *,
    code: str,
) -> WebImpactApprovedTarget:
    value = _exact_dict(raw, _TARGET_KEYS, code)
    try:
        return WebImpactApprovedTarget(
            kind=value["kind"],
            binding_sha256=value["binding_sha256"],
            generation=value["generation"],
        )
    except (TypeError, ValueError) as error:
        raise WebImpactExecutionPreflightError(code) from error


def _current_target_matches(
    declared: WebImpactApprovedTarget,
    current: WebImpactApprovedTarget,
) -> bool:
    return (
        type(current) is WebImpactApprovedTarget
        and declared == current
    )


def parse_web_impact_operator_spec(
    payload: bytes,
    *,
    current_source_manifest_sha256: str,
    current_runtime_image_digest: str,
    current_vulnerable_target: WebImpactApprovedTarget,
    current_control_target: WebImpactApprovedTarget | None = None,
) -> WebImpactExecutionSpecification:
    """Parse and freeze one strict value-free operator execution spec.

    The target commitments passed through ``current_*`` must be read from the
    current challenge configuration immediately before this call.  The same
    commitments are required again by :func:`evaluate_web_impact_execution`
    before the result can be accepted.
    """

    if type(payload) is not bytes or not payload:
        raise WebImpactExecutionPreflightError("operator_spec_payload_invalid")
    if len(payload) > WEB_IMPACT_OPERATOR_SPEC_MAX_BYTES:
        raise WebImpactExecutionPreflightError("operator_spec_size_exceeded")
    try:
        parsed = strict_json_loads(
            payload,
            max_bytes=WEB_IMPACT_OPERATOR_SPEC_MAX_BYTES,
            max_depth=16,
        )
    except (StrictJSONError, UnicodeError, ValueError) as error:
        raise WebImpactExecutionPreflightError(
            "operator_spec_json_invalid"
        ) from error
    root = _exact_dict(
        parsed,
        _OPERATOR_SPEC_KEYS,
        "operator_spec_schema_invalid",
    )
    if (
        root["protocol"] != WEB_IMPACT_OPERATOR_SPEC_PROTOCOL
        or root["schema_version"] != WEB_IMPACT_EXECUTION_SCHEMA_VERSION
    ):
        raise WebImpactExecutionPreflightError(
            "operator_spec_protocol_invalid"
        )
    if (
        not _valid_sha256(current_source_manifest_sha256)
        or root["source_manifest_sha256"]
        != current_source_manifest_sha256
    ):
        raise WebImpactExecutionPreflightError(
            "source_manifest_binding_mismatch"
        )
    if (
        not _valid_image_digest(current_runtime_image_digest)
        or root["runtime_image_digest"]
        != current_runtime_image_digest
    ):
        raise WebImpactExecutionPreflightError(
            "runtime_image_binding_mismatch"
        )

    vulnerable_target = _parse_target(
        root["authorized_target"],
        code="vulnerable_target_invalid",
    )
    if (
        type(current_vulnerable_target) is not WebImpactApprovedTarget
        or not _current_target_matches(
            vulnerable_target,
            current_vulnerable_target,
        )
    ):
        raise WebImpactExecutionPreflightError(
            "vulnerable_target_not_current"
        )

    identities_raw = root["identities"]
    if (
        type(identities_raw) is not list
        or len(identities_raw) != len(WEB_IDENTITY_ROLES)
    ):
        raise WebImpactExecutionPreflightError("identity_schema_invalid")
    identities: list[WebIdentityBinding] = []
    for raw in identities_raw:
        value = _exact_dict(
            raw,
            _IDENTITY_KEYS,
            "identity_schema_invalid",
        )
        identities.append(
            WebIdentityBinding(
                role=value["role"],
                principal_binding_sha256=value[
                    "principal_binding_sha256"
                ],
            )
        )

    timeline_raw = root["timeline"]
    if (
        type(timeline_raw) is not list
        or not 2 <= len(timeline_raw) <= WEB_IMPACT_MAX_TIMELINE_STEPS
    ):
        raise WebImpactExecutionPreflightError("timeline_schema_invalid")
    timeline: list[WebTimelineStep] = []
    for raw in timeline_raw:
        value = _exact_dict(
            raw,
            _TIMELINE_KEYS,
            "timeline_schema_invalid",
        )
        try:
            timeline.append(
                WebTimelineStep(
                    ordinal=value["ordinal"],
                    channel=value["channel"],
                    role=value["role"],
                    method=value["method"],
                    route_binding_sha256=value[
                        "route_binding_sha256"
                    ],
                    request_shape_sha256=value[
                        "request_shape_sha256"
                    ],
                    expected_status=value["expected_status"],
                )
            )
        except TypeError as error:
            raise WebImpactExecutionPreflightError(
                "timeline_schema_invalid"
            ) from error

    source_sink_raw = _exact_dict(
        root["source_sink"],
        _SOURCE_SINK_KEYS,
        "source_sink_schema_invalid",
    )
    oracle_raw = _exact_dict(
        root["oracle"],
        _ORACLE_KEYS,
        "oracle_schema_invalid",
    )
    try:
        source_sink = WebSourceSinkContract(
            source_kind=source_sink_raw["source_kind"],
            source_pointer_sha256=source_sink_raw[
                "source_pointer_sha256"
            ],
            sink_kind=source_sink_raw["sink_kind"],
            sink_pointer_sha256=source_sink_raw[
                "sink_pointer_sha256"
            ],
            runtime_step_ordinal=source_sink_raw[
                "runtime_step_ordinal"
            ],
            trace_contract_sha256=source_sink_raw[
                "trace_contract_sha256"
            ],
        )
        oracle = WebImpactOracle(
            impact_kind=oracle_raw["impact_kind"],
            sink_step_ordinal=oracle_raw["sink_step_ordinal"],
            expected_status=oracle_raw["expected_status"],
            expected_response_sha256=oracle_raw[
                "expected_response_sha256"
            ],
            expected_response_size_bytes=oracle_raw[
                "expected_response_size_bytes"
            ],
        )
    except TypeError as error:
        raise WebImpactExecutionPreflightError(
            "source_sink_or_oracle_schema_invalid"
        ) from error

    differential: WebDifferentialPolicy | None = None
    control_target: WebImpactApprovedTarget | None = None
    if root["differential"] is not None:
        differential_raw = _exact_dict(
            root["differential"],
            _DIFFERENTIAL_KEYS,
            "differential_schema_invalid",
        )
        control_target = _parse_target(
            differential_raw["target"],
            code="control_target_invalid",
        )
        if (
            type(current_control_target) is not WebImpactApprovedTarget
            or not _current_target_matches(
                control_target,
                current_control_target,
            )
        ):
            raise WebImpactExecutionPreflightError(
                "control_target_not_current"
            )
        try:
            differential = WebDifferentialPolicy(
                control_target_binding_sha256=(
                    control_target.binding_sha256
                ),
                control_target_generation=control_target.generation,
                expected_status=differential_raw["expected_status"],
                expected_response_sha256=differential_raw[
                    "expected_response_sha256"
                ],
                expected_response_size_bytes=differential_raw[
                    "expected_response_size_bytes"
                ],
            )
        except TypeError as error:
            raise WebImpactExecutionPreflightError(
                "differential_schema_invalid"
            ) from error
    elif current_control_target is not None:
        raise WebImpactExecutionPreflightError(
            "unexpected_current_control_target"
        )

    try:
        plan = build_web_impact_plan(
            source_manifest_sha256=root["source_manifest_sha256"],
            runtime_image_digest=root["runtime_image_digest"],
            authorized_target_binding_sha256=(
                vulnerable_target.binding_sha256
            ),
            target_generation=vulnerable_target.generation,
            identities=identities,
            timeline=timeline,
            source_sink=source_sink,
            oracle=oracle,
            differential=differential,
        )
    except (TypeError, ValueError, WebImpactPreflightError) as error:
        code = (
            error.code
            if isinstance(error, WebImpactPreflightError)
            else "operator_semantics_invalid"
        )
        raise WebImpactExecutionPreflightError(
            f"web_impact_plan_{code}"
        ) from error

    specification = WebImpactExecutionSpecification(
        plan=plan,
        operator_spec_sha256=_sha256(payload),
        operator_spec_size_bytes=len(payload),
        vulnerable_target=vulnerable_target,
        control_target=control_target,
    )
    try:
        specification.canonical_bytes
    except ValueError as error:
        raise WebImpactExecutionPreflightError(
            "execution_specification_size_exceeded"
        ) from error
    return specification


@dataclass(frozen=True, slots=True)
class WebImpactReplayIssue:
    """Engine-owned identifiers and raw freshness entropy for one replay."""

    request_id: str
    run_id: str
    replay_nonce: bytes


@dataclass(frozen=True, slots=True)
class WebImpactReplayRequest:
    """Canonical request committed before the corresponding observation."""

    request_id: str
    run_id: str
    replay_target_kind: str
    replay_ordinal: int
    replay_nonce_sha256: str
    identity_epoch_sha256: str
    semantic_execution_contract_sha256: str
    transport_execution_contract_sha256: str
    operator_spec_sha256: str
    plan_sha256: str
    source_manifest_sha256: str
    runtime_image_digest: str
    target: WebImpactApprovedTarget

    def to_dict(self) -> dict[str, object]:
        return {
            "identity_epoch_sha256": self.identity_epoch_sha256,
            "network_policy": {
                "kind": "exact_preapproved_target_only",
                "target": self.target.to_dict(),
            },
            "operator_spec_sha256": self.operator_spec_sha256,
            "plan_sha256": self.plan_sha256,
            "protocol": WEB_IMPACT_EXECUTION_PROTOCOL,
            "replay_nonce_sha256": self.replay_nonce_sha256,
            "replay_ordinal": self.replay_ordinal,
            "replay_target_kind": self.replay_target_kind,
            "request_id": self.request_id,
            "run_id": self.run_id,
            "runtime_image_digest": self.runtime_image_digest,
            "schema_version": WEB_IMPACT_EXECUTION_SCHEMA_VERSION,
            "semantic_execution_contract_sha256": (
                self.semantic_execution_contract_sha256
            ),
            "source_manifest_sha256": self.source_manifest_sha256,
            "transport_contract": {
                "artifact_capture": "complete_exact_bytes",
                "browser_and_http_timeline": "ordered",
                "fresh_identity_state": True,
                "fresh_workspace": True,
                "identity_roles": list(WEB_IDENTITY_ROLES),
                "network": "exact_preapproved_target_only",
                "replay_count": WEB_IMPACT_REPLAY_COUNT,
                "transport_execution_contract_sha256": (
                    self.transport_execution_contract_sha256
                ),
            },
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(
            self.to_dict(),
            maximum_bytes=WEB_IMPACT_EXECUTION_REQUEST_MAX_BYTES,
        )

    @property
    def request_sha256(self) -> str:
        return _sha256(self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class WebImpactExecutionPlan:
    """One complete pre-issued replay wave."""

    specification: WebImpactExecutionSpecification
    requests: tuple[WebImpactReplayRequest, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "operator_spec_sha256": (
                self.specification.operator_spec_sha256
            ),
            "plan_sha256": self.specification.plan.plan_sha256,
            "protocol": WEB_IMPACT_EXECUTION_PROTOCOL,
            "requests": [
                {
                    **item.to_dict(),
                    "request_sha256": item.request_sha256,
                }
                for item in self.requests
            ],
            "schema_version": WEB_IMPACT_EXECUTION_SCHEMA_VERSION,
            "specification_sha256": (
                self.specification.specification_sha256
            ),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(
            self.to_dict(),
            maximum_bytes=WEB_IMPACT_EXECUTION_PLAN_MAX_BYTES,
        )

    @property
    def execution_plan_sha256(self) -> str:
        return _sha256(self.canonical_bytes)


def _transport_execution_contract_sha256(
    specification: WebImpactExecutionSpecification,
    *,
    request_id: str,
    run_id: str,
    replay_target_kind: str,
    replay_ordinal: int,
    replay_nonce_sha256: str,
    identity_epoch_sha256: str,
    semantic_execution_contract_sha256: str,
    target: WebImpactApprovedTarget,
) -> str:
    return _sha256(
        _canonical_json_bytes(
            {
                "identity_epoch_sha256": identity_epoch_sha256,
                "operator_spec_sha256": (
                    specification.operator_spec_sha256
                ),
                "plan_sha256": specification.plan.plan_sha256,
                "protocol": WEB_IMPACT_EXECUTION_PROTOCOL,
                "replay_nonce_sha256": replay_nonce_sha256,
                "replay_ordinal": replay_ordinal,
                "replay_target_kind": replay_target_kind,
                "request_id": request_id,
                "run_id": run_id,
                "semantic_execution_contract_sha256": (
                    semantic_execution_contract_sha256
                ),
                "target": target.to_dict(),
            }
        )
    )


def plan_web_impact_execution(
    specification: WebImpactExecutionSpecification,
    issues: Iterable[WebImpactReplayIssue],
) -> WebImpactExecutionPlan:
    """Pre-issue every replay before any result may be considered."""

    if type(specification) is not WebImpactExecutionSpecification:
        raise WebImpactExecutionPreflightError(
            "execution_specification_invalid"
        )
    expected_count = WEB_IMPACT_REPLAY_COUNT * (
        2 if specification.control_target is not None else 1
    )
    issue_values = _bounded_tuple(
        issues,
        expected=expected_count,
        code="replay_issue_count_mismatch",
    )
    request_ids: set[str] = set()
    run_ids: set[str] = set()
    all_ids: set[str] = set()
    nonces: set[str] = set()
    requests: list[WebImpactReplayRequest] = []
    for position, raw in enumerate(issue_values, start=1):
        if type(raw) is not WebImpactReplayIssue:
            raise WebImpactExecutionPreflightError(
                f"replay-{position}:issue_type_invalid"
            )
        if not _valid_id(raw.request_id) or not _valid_id(raw.run_id):
            raise WebImpactExecutionPreflightError(
                f"replay-{position}:issued_identifier_invalid"
            )
        if (
            raw.request_id in request_ids
            or raw.run_id in run_ids
            or raw.request_id in all_ids
            or raw.run_id in all_ids
            or raw.request_id == raw.run_id
        ):
            raise WebImpactExecutionPreflightError(
                f"replay-{position}:issued_identifier_reused"
            )
        if (
            type(raw.replay_nonce) is not bytes
            or not WEB_IMPACT_REPLAY_NONCE_MIN_BYTES
            <= len(raw.replay_nonce)
            <= WEB_IMPACT_REPLAY_NONCE_MAX_BYTES
        ):
            raise WebImpactExecutionPreflightError(
                f"replay-{position}:nonce_invalid"
            )
        nonce_sha256 = _sha256(raw.replay_nonce)
        if nonce_sha256 in nonces:
            raise WebImpactExecutionPreflightError(
                f"replay-{position}:nonce_reused"
            )
        request_ids.add(raw.request_id)
        run_ids.add(raw.run_id)
        all_ids.update((raw.request_id, raw.run_id))
        nonces.add(nonce_sha256)

        control = position > WEB_IMPACT_REPLAY_COUNT
        replay_target_kind = "control" if control else "vulnerable"
        replay_ordinal = (
            position - WEB_IMPACT_REPLAY_COUNT
            if control
            else position
        )
        target = (
            specification.control_target
            if control
            else specification.vulnerable_target
        )
        if target is None:
            raise WebImpactExecutionPreflightError(
                f"replay-{position}:control_target_missing"
            )
        identity_epoch = web_identity_epoch_sha256(
            specification.plan,
            nonce_sha256,
        )
        semantic_contract = web_replay_execution_contract_sha256(
            specification.plan,
            target_kind=replay_target_kind,
            replay_ordinal=replay_ordinal,
            replay_nonce_sha256=nonce_sha256,
        )
        transport_contract = _transport_execution_contract_sha256(
            specification,
            request_id=raw.request_id,
            run_id=raw.run_id,
            replay_target_kind=replay_target_kind,
            replay_ordinal=replay_ordinal,
            replay_nonce_sha256=nonce_sha256,
            identity_epoch_sha256=identity_epoch,
            semantic_execution_contract_sha256=semantic_contract,
            target=target,
        )
        request = WebImpactReplayRequest(
            request_id=raw.request_id,
            run_id=raw.run_id,
            replay_target_kind=replay_target_kind,
            replay_ordinal=replay_ordinal,
            replay_nonce_sha256=nonce_sha256,
            identity_epoch_sha256=identity_epoch,
            semantic_execution_contract_sha256=semantic_contract,
            transport_execution_contract_sha256=transport_contract,
            operator_spec_sha256=(
                specification.operator_spec_sha256
            ),
            plan_sha256=specification.plan.plan_sha256,
            source_manifest_sha256=(
                specification.plan.source_manifest_sha256
            ),
            runtime_image_digest=(
                specification.plan.runtime_image_digest
            ),
            target=target,
        )
        try:
            request.canonical_bytes
        except ValueError as error:
            raise WebImpactExecutionPreflightError(
                f"replay-{position}:request_size_exceeded"
            ) from error
        requests.append(request)

    if (
        len({item.request_sha256 for item in requests})
        != len(requests)
        or len(
            {
                item.transport_execution_contract_sha256
                for item in requests
            }
        )
        != len(requests)
    ):
        raise WebImpactExecutionPreflightError(
            "issued_request_commitment_reused"
        )
    result = WebImpactExecutionPlan(
        specification=specification,
        requests=tuple(requests),
    )
    try:
        result.canonical_bytes
    except ValueError as error:
        raise WebImpactExecutionPreflightError(
            "execution_plan_size_exceeded"
        ) from error
    return result


@dataclass(frozen=True, slots=True)
class WebImpactCapturedArtifact:
    """Raw payload retained only long enough for independent hashing."""

    artifact_id: str
    payload: bytes


def _observation_commitment_dict(
    observation: WebImpactReplayObservation,
) -> dict[str, object]:
    """Serialize every value-free observation field except receipt hash.

    The receipt hash is excluded to avoid a circular commitment: the receipt
    commits to this document, and the semantic observation then points to the
    receipt hash.
    """

    return {
        "authorized_target_binding_sha256": (
            observation.authorized_target_binding_sha256
        ),
        "capture": {
            "capture_complete": observation.capture_complete,
            "capture_error": observation.capture_error,
            "truncated": observation.truncated,
            "truncation_known": observation.truncation_known,
        },
        "execution_contract_sha256": (
            observation.execution_contract_sha256
        ),
        "identity_epoch_sha256": observation.identity_epoch_sha256,
        "plan_sha256": observation.plan_sha256,
        "receipt_id": observation.receipt_id,
        "replay_nonce_sha256": observation.replay_nonce_sha256,
        "replay_ordinal": observation.replay_ordinal,
        "run_id": observation.run_id,
        "runtime_image_digest": observation.runtime_image_digest,
        "source_manifest_sha256": observation.source_manifest_sha256,
        "source_sink": observation.source_sink.to_dict(),
        "target_generation": observation.target_generation,
        "target_kind": observation.target_kind,
        "timeline": [item.to_dict() for item in observation.timeline],
        "transport": {
            "clean_workspace": observation.clean_workspace,
            "exit_code": observation.exit_code,
            "fresh_identity_state": observation.fresh_identity_state,
            "network_target_authorized": (
                observation.network_target_authorized
            ),
            "orchestration_status": observation.orchestration_status,
            "timed_out": observation.timed_out,
        },
    }


def web_impact_observation_commitment_sha256(
    observation: WebImpactReplayObservation,
) -> str:
    if type(observation) is not WebImpactReplayObservation:
        raise TypeError(
            "observation must be an exact WebImpactReplayObservation"
        )
    return _sha256(_canonical_json_bytes(_observation_commitment_dict(observation)))


def _artifact_entries(
    observation: WebImpactReplayObservation,
) -> tuple[tuple[str, WebArtifactCommitment, int], ...]:
    entries: list[tuple[str, WebArtifactCommitment, int]] = []
    for event in observation.timeline:
        entries.append(
            (
                f"timeline-{event.ordinal}:request",
                event.request_artifact,
                WEB_IMPACT_MAX_ARTIFACT_BYTES,
            )
        )
        entries.append(
            (
                f"timeline-{event.ordinal}:response",
                event.response_artifact,
                WEB_IMPACT_MAX_ARTIFACT_BYTES,
            )
        )
    entries.append(
        (
            "source_sink:runtime_trace",
            observation.source_sink.trace_artifact,
            WEB_IMPACT_MAX_TRACE_BYTES,
        )
    )
    return tuple(entries)


def _artifact_commitment_is_bounded(
    artifact: object,
    *,
    maximum_bytes: int,
) -> bool:
    return (
        type(artifact) is WebArtifactCommitment
        and _valid_id(artifact.artifact_id)
        and _valid_sha256(artifact.sha256)
        and type(artifact.size_bytes) is int
        and 0 <= artifact.size_bytes <= maximum_bytes
    )


def _observation_is_bounded(
    observation: object,
    *,
    expected_timeline_steps: int | None = None,
) -> bool:
    if (
        type(observation) is not WebImpactReplayObservation
        or type(observation.timeline) is not tuple
        or not 2
        <= len(observation.timeline)
        <= WEB_IMPACT_MAX_TIMELINE_STEPS
        or (
            expected_timeline_steps is not None
            and len(observation.timeline) != expected_timeline_steps
        )
        or type(observation.source_sink) is not WebSourceSinkObservation
    ):
        return False
    for event in observation.timeline:
        if (
            type(event) is not WebTimelineEvent
            or type(event.ordinal) is not int
            or event.channel not in {"browser", "http"}
            or event.role not in WEB_IDENTITY_ROLES
            or type(event.method) is not str
            or not 1 <= len(event.method) <= 16
            or not event.method.isascii()
            or not event.method.isupper()
            or not _valid_sha256(event.route_binding_sha256)
            or not _valid_sha256(event.request_shape_sha256)
            or type(event.status) is not int
            or not 100 <= event.status <= 599
            or not _artifact_commitment_is_bounded(
                event.request_artifact,
                maximum_bytes=WEB_IMPACT_MAX_ARTIFACT_BYTES,
            )
            or not _artifact_commitment_is_bounded(
                event.response_artifact,
                maximum_bytes=WEB_IMPACT_MAX_ARTIFACT_BYTES,
            )
            or not _valid_sha256(event.cookie_transition_sha256)
            or not _valid_sha256(event.security_context_sha256)
        ):
            return False
    source_sink = observation.source_sink
    return (
        type(source_sink.source_kind) is str
        and 1 <= len(source_sink.source_kind) <= 64
        and source_sink.source_kind.isascii()
        and type(source_sink.sink_kind) is str
        and 1 <= len(source_sink.sink_kind) <= 64
        and source_sink.sink_kind.isascii()
        and _valid_sha256(source_sink.source_pointer_sha256)
        and _valid_sha256(source_sink.sink_pointer_sha256)
        and type(source_sink.runtime_step_ordinal) is int
        and 1
        <= source_sink.runtime_step_ordinal
        <= len(observation.timeline)
        and _valid_sha256(source_sink.runtime_request_sha256)
        and _valid_sha256(source_sink.trace_contract_sha256)
        and _artifact_commitment_is_bounded(
            source_sink.trace_artifact,
            maximum_bytes=WEB_IMPACT_MAX_TRACE_BYTES,
        )
        and type(source_sink.reached_sink) is bool
    )


def _artifact_manifest_dict(
    observation: WebImpactReplayObservation,
) -> dict[str, object]:
    return {
        "artifacts": [
            {
                "artifact_id": artifact.artifact_id,
                "label": label,
                "sha256": artifact.sha256,
                "size_bytes": artifact.size_bytes,
            }
            for label, artifact, _maximum in _artifact_entries(observation)
        ],
        "kind": "ordered_exact_payload_commitments_v1",
    }


def web_impact_artifact_manifest_sha256(
    observation: WebImpactReplayObservation,
) -> str:
    if type(observation) is not WebImpactReplayObservation:
        raise TypeError(
            "observation must be an exact WebImpactReplayObservation"
        )
    return _sha256(_canonical_json_bytes(_artifact_manifest_dict(observation)))


@dataclass(frozen=True, slots=True)
class WebImpactExecutionReceipt:
    """Canonical, raw-free attestation produced after one sandbox replay."""

    request_id: str
    run_id: str
    receipt_id: str
    request_sha256: str
    replay_target_kind: str
    replay_ordinal: int
    replay_nonce_sha256: str
    identity_epoch_sha256: str
    semantic_execution_contract_sha256: str
    transport_execution_contract_sha256: str
    operator_spec_sha256: str
    plan_sha256: str
    target: WebImpactApprovedTarget
    observation_commitment_sha256: str
    artifact_manifest_sha256: str
    orchestration_status: str
    exit_code: int | None
    timed_out: bool
    clean_workspace: bool
    fresh_identity_state: bool
    network_target_authorized: bool
    capture_complete: bool
    truncation_known: bool
    truncated: bool | None
    capture_error_code: str | None

    def __post_init__(self) -> None:
        for value in (
            self.request_id,
            self.run_id,
            self.receipt_id,
        ):
            if not _valid_id(value):
                raise ValueError("receipt_identifier_invalid")
        for value in (
            self.request_sha256,
            self.replay_nonce_sha256,
            self.identity_epoch_sha256,
            self.semantic_execution_contract_sha256,
            self.transport_execution_contract_sha256,
            self.operator_spec_sha256,
            self.plan_sha256,
            self.observation_commitment_sha256,
            self.artifact_manifest_sha256,
        ):
            if not _valid_sha256(value):
                raise ValueError("receipt_hash_invalid")
        if (
            self.replay_target_kind not in _REPLAY_TARGET_KINDS
            or type(self.replay_ordinal) is not int
            or not 1 <= self.replay_ordinal <= WEB_IMPACT_REPLAY_COUNT
            or type(self.target) is not WebImpactApprovedTarget
        ):
            raise ValueError("receipt_replay_binding_invalid")
        if self.orchestration_status not in _RECEIPT_STATUSES:
            raise ValueError("receipt_status_invalid")
        if self.exit_code is not None and (
            type(self.exit_code) is not int
            or not -255 <= self.exit_code <= 255
        ):
            raise ValueError("receipt_exit_code_invalid")
        for value in (
            self.timed_out,
            self.clean_workspace,
            self.fresh_identity_state,
            self.network_target_authorized,
            self.capture_complete,
            self.truncation_known,
        ):
            if type(value) is not bool:
                raise ValueError("receipt_boolean_invalid")
        if self.truncated is not None and type(self.truncated) is not bool:
            raise ValueError("receipt_truncated_invalid")
        if (
            self.capture_error_code is not None
            and self.capture_error_code not in _CAPTURE_ERROR_CODES
        ):
            raise ValueError("receipt_capture_error_code_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_manifest_sha256": self.artifact_manifest_sha256,
            "capture": {
                "capture_complete": self.capture_complete,
                "capture_error_code": self.capture_error_code,
                "truncated": self.truncated,
                "truncation_known": self.truncation_known,
            },
            "identity_epoch_sha256": self.identity_epoch_sha256,
            "observation_commitment_sha256": (
                self.observation_commitment_sha256
            ),
            "operator_spec_sha256": self.operator_spec_sha256,
            "plan_sha256": self.plan_sha256,
            "protocol": WEB_IMPACT_EXECUTION_PROTOCOL,
            "receipt_id": self.receipt_id,
            "replay_nonce_sha256": self.replay_nonce_sha256,
            "replay_ordinal": self.replay_ordinal,
            "replay_target_kind": self.replay_target_kind,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "run_id": self.run_id,
            "schema_version": WEB_IMPACT_EXECUTION_SCHEMA_VERSION,
            "semantic_execution_contract_sha256": (
                self.semantic_execution_contract_sha256
            ),
            "target": self.target.to_dict(),
            "transport": {
                "clean_workspace": self.clean_workspace,
                "exit_code": self.exit_code,
                "fresh_identity_state": self.fresh_identity_state,
                "network_target_authorized": (
                    self.network_target_authorized
                ),
                "orchestration_status": self.orchestration_status,
                "timed_out": self.timed_out,
            },
            "transport_execution_contract_sha256": (
                self.transport_execution_contract_sha256
            ),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(
            self.to_dict(),
            maximum_bytes=WEB_IMPACT_EXECUTION_RECEIPT_MAX_BYTES,
        )

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)

    @classmethod
    def from_payload(cls, payload: bytes) -> "WebImpactExecutionReceipt":
        if (
            type(payload) is not bytes
            or not payload
            or len(payload) > WEB_IMPACT_EXECUTION_RECEIPT_MAX_BYTES
        ):
            raise ValueError("receipt_payload_invalid")
        try:
            raw = strict_json_loads(
                payload,
                max_bytes=WEB_IMPACT_EXECUTION_RECEIPT_MAX_BYTES,
                max_depth=12,
            )
        except (StrictJSONError, UnicodeError, ValueError) as error:
            raise ValueError("receipt_json_invalid") from error
        root = _receipt_exact_dict(raw, _RECEIPT_KEYS)
        if (
            root["protocol"] != WEB_IMPACT_EXECUTION_PROTOCOL
            or root["schema_version"]
            != WEB_IMPACT_EXECUTION_SCHEMA_VERSION
        ):
            raise ValueError("receipt_protocol_invalid")
        target_raw = _receipt_exact_dict(root["target"], _TARGET_KEYS)
        capture = _receipt_exact_dict(
            root["capture"],
            _RECEIPT_CAPTURE_KEYS,
        )
        transport = _receipt_exact_dict(
            root["transport"],
            _RECEIPT_TRANSPORT_KEYS,
        )
        try:
            receipt = cls(
                request_id=root["request_id"],
                run_id=root["run_id"],
                receipt_id=root["receipt_id"],
                request_sha256=root["request_sha256"],
                replay_target_kind=root["replay_target_kind"],
                replay_ordinal=root["replay_ordinal"],
                replay_nonce_sha256=root["replay_nonce_sha256"],
                identity_epoch_sha256=root["identity_epoch_sha256"],
                semantic_execution_contract_sha256=root[
                    "semantic_execution_contract_sha256"
                ],
                transport_execution_contract_sha256=root[
                    "transport_execution_contract_sha256"
                ],
                operator_spec_sha256=root["operator_spec_sha256"],
                plan_sha256=root["plan_sha256"],
                target=WebImpactApprovedTarget(
                    kind=target_raw["kind"],
                    binding_sha256=target_raw["binding_sha256"],
                    generation=target_raw["generation"],
                ),
                observation_commitment_sha256=root[
                    "observation_commitment_sha256"
                ],
                artifact_manifest_sha256=root[
                    "artifact_manifest_sha256"
                ],
                orchestration_status=transport[
                    "orchestration_status"
                ],
                exit_code=transport["exit_code"],
                timed_out=transport["timed_out"],
                clean_workspace=transport["clean_workspace"],
                fresh_identity_state=transport[
                    "fresh_identity_state"
                ],
                network_target_authorized=transport[
                    "network_target_authorized"
                ],
                capture_complete=capture["capture_complete"],
                truncation_known=capture["truncation_known"],
                truncated=capture["truncated"],
                capture_error_code=capture["capture_error_code"],
            )
        except (TypeError, ValueError) as error:
            raise ValueError("receipt_fields_invalid") from error
        if payload != receipt.canonical_bytes:
            raise ValueError("receipt_not_canonical")
        return receipt


def _receipt_exact_dict(
    value: object,
    keys: frozenset[str],
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise ValueError("receipt_schema_invalid")
    return value


def _validate_captured_artifacts(
    observation: WebImpactReplayObservation,
    artifacts: tuple[WebImpactCapturedArtifact, ...],
    *,
    used_artifact_ids: set[str] | None = None,
) -> tuple[str | None, int]:
    expected = _artifact_entries(observation)
    if type(artifacts) is not tuple or len(artifacts) != len(expected):
        return "artifact_capture_count_mismatch", 0
    consumed = 0
    local_ids: set[str] = set()
    for captured, (_label, commitment, maximum) in zip(
        artifacts,
        expected,
        strict=True,
    ):
        if (
            type(captured) is not WebImpactCapturedArtifact
            or not _valid_id(captured.artifact_id)
            or captured.artifact_id != commitment.artifact_id
            or type(captured.payload) is not bytes
        ):
            return "artifact_capture_binding_mismatch", consumed
        if (
            captured.artifact_id in local_ids
            or (
                used_artifact_ids is not None
                and captured.artifact_id in used_artifact_ids
            )
        ):
            return "duplicate_artifact_id", consumed
        size = len(captured.payload)
        if (
            size > maximum
            or size != commitment.size_bytes
            or _sha256(captured.payload) != commitment.sha256
        ):
            return "artifact_payload_mismatch", consumed
        consumed += size
        if consumed > WEB_IMPACT_EXECUTION_MAX_CAPTURE_BYTES:
            return "artifact_capture_total_size_exceeded", consumed
        local_ids.add(captured.artifact_id)
    if used_artifact_ids is not None:
        used_artifact_ids.update(local_ids)
    return None, consumed


def build_web_impact_execution_receipt(
    request: WebImpactReplayRequest,
    observation: WebImpactReplayObservation,
    artifacts: tuple[WebImpactCapturedArtifact, ...],
    *,
    orchestration_status: str,
    exit_code: int | None,
    timed_out: bool,
    clean_workspace: bool,
    fresh_identity_state: bool,
    network_target_authorized: bool,
    capture_complete: bool,
    truncation_known: bool,
    truncated: bool | None,
    capture_error_code: str | None,
) -> WebImpactExecutionReceipt:
    """Build the raw-free receipt that the engine persists after a replay."""

    if type(request) is not WebImpactReplayRequest:
        raise WebImpactExecutionPreflightError("issued_request_invalid")
    if not _observation_is_bounded(observation):
        raise WebImpactExecutionPreflightError("observation_type_invalid")
    error, _consumed = _validate_captured_artifacts(
        observation,
        artifacts,
    )
    if error is not None:
        raise WebImpactExecutionPreflightError(error)
    try:
        return WebImpactExecutionReceipt(
            request_id=request.request_id,
            run_id=request.run_id,
            receipt_id=observation.receipt_id,
            request_sha256=request.request_sha256,
            replay_target_kind=request.replay_target_kind,
            replay_ordinal=request.replay_ordinal,
            replay_nonce_sha256=request.replay_nonce_sha256,
            identity_epoch_sha256=request.identity_epoch_sha256,
            semantic_execution_contract_sha256=(
                request.semantic_execution_contract_sha256
            ),
            transport_execution_contract_sha256=(
                request.transport_execution_contract_sha256
            ),
            operator_spec_sha256=request.operator_spec_sha256,
            plan_sha256=request.plan_sha256,
            target=request.target,
            observation_commitment_sha256=(
                web_impact_observation_commitment_sha256(observation)
            ),
            artifact_manifest_sha256=(
                web_impact_artifact_manifest_sha256(observation)
            ),
            orchestration_status=orchestration_status,
            exit_code=exit_code,
            timed_out=timed_out,
            clean_workspace=clean_workspace,
            fresh_identity_state=fresh_identity_state,
            network_target_authorized=network_target_authorized,
            capture_complete=capture_complete,
            truncation_known=truncation_known,
            truncated=truncated,
            capture_error_code=capture_error_code,
        )
    except (TypeError, ValueError) as error:
        raise WebImpactExecutionPreflightError(
            "receipt_fields_invalid"
        ) from error


@dataclass(frozen=True, slots=True)
class WebImpactReplayTransportObservation:
    """One durable request, receipt, semantic observation, and raw capture."""

    request_payload: bytes
    receipt_payload: bytes
    semantic_observation: WebImpactReplayObservation
    artifacts: tuple[WebImpactCapturedArtifact, ...]


@dataclass(frozen=True, slots=True)
class WebImpactExecutionRecord:
    replay_target_kind: str
    replay_ordinal: int
    request_id: str
    request_sha256: str
    run_id: str
    receipt_id: str
    receipt_sha256: str
    replay_nonce_sha256: str
    semantic_execution_contract_sha256: str
    transport_execution_contract_sha256: str
    observation_commitment_sha256: str
    artifact_manifest_sha256: str
    target: WebImpactApprovedTarget

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_manifest_sha256": self.artifact_manifest_sha256,
            "observation_commitment_sha256": (
                self.observation_commitment_sha256
            ),
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "replay_nonce_sha256": self.replay_nonce_sha256,
            "replay_ordinal": self.replay_ordinal,
            "replay_target_kind": self.replay_target_kind,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "run_id": self.run_id,
            "semantic_execution_contract_sha256": (
                self.semantic_execution_contract_sha256
            ),
            "target": self.target.to_dict(),
            "transport_execution_contract_sha256": (
                self.transport_execution_contract_sha256
            ),
        }


@dataclass(frozen=True, slots=True)
class WebImpactExecutionEvaluation:
    """Raw-free transport result plus the reused semantic evaluation."""

    verdict: WebImpactExecutionVerdict
    reason_codes: tuple[str, ...]
    execution_plan_sha256: str | None
    records: tuple[WebImpactExecutionRecord, ...]
    semantic_evaluation: WebImpactEvaluation | None

    @property
    def confirmed(self) -> bool:
        return (
            self.verdict is WebImpactExecutionVerdict.CONFIRMED
            and not self.reason_codes
            and self.execution_plan_sha256 is not None
            and self.semantic_evaluation is not None
            and self.semantic_evaluation.verdict
            is WebImpactVerdict.CONFIRMED
            and self.semantic_evaluation.passed
            and len(self.records)
            == len(self.semantic_evaluation.replay_records)
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "authorities": {
                **_NON_AUTHORITIES,
                "executed_web_impact_fact_authorized": self.confirmed,
                "progress_marker_authorized": self.confirmed,
                "web_impact_oracle_satisfied": self.confirmed,
            },
            "confirmed": self.confirmed,
            "execution_plan_sha256": self.execution_plan_sha256,
            "protocol": WEB_IMPACT_EXECUTION_PROTOCOL,
            "reason_codes": list(self.reason_codes),
            "records": [item.to_dict() for item in self.records],
            "schema_version": WEB_IMPACT_EXECUTION_SCHEMA_VERSION,
            "semantic_evaluation": (
                self.semantic_evaluation.to_dict()
                if self.semantic_evaluation is not None
                else None
            ),
            "semantic_evaluation_sha256": (
                self.semantic_evaluation.sha256
                if self.semantic_evaluation is not None
                else None
            ),
            "verdict": self.verdict.value,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(
            self.to_dict(),
            maximum_bytes=WEB_IMPACT_EXECUTION_EVALUATION_MAX_BYTES,
        )

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)

    def reduction_projection(self) -> dict[str, object]:
        if not self.confirmed or self.semantic_evaluation is None:
            return {
                "automatic_submission": False,
                "candidate": None,
                "executed_fact": None,
                "impact": None,
                "progress": None,
                "proof": None,
            }
        result = dict(self.semantic_evaluation.reduction_projection())
        result["automatic_submission"] = False
        result["candidate"] = None
        result["impact"] = None
        result["proof"] = None
        return result


def _rejected(
    code: str,
    *,
    execution_plan: WebImpactExecutionPlan | None = None,
    records: tuple[WebImpactExecutionRecord, ...] = (),
    semantic: WebImpactEvaluation | None = None,
) -> WebImpactExecutionEvaluation:
    return WebImpactExecutionEvaluation(
        verdict=WebImpactExecutionVerdict.REJECTED,
        reason_codes=(code,),
        execution_plan_sha256=(
            execution_plan.execution_plan_sha256
            if execution_plan is not None
            else None
        ),
        records=records,
        semantic_evaluation=semantic,
    )


def _current_bindings_match(
    execution_plan: WebImpactExecutionPlan,
    *,
    current_source_manifest_sha256: str,
    current_runtime_image_digest: str,
    current_vulnerable_target: WebImpactApprovedTarget,
    current_control_target: WebImpactApprovedTarget | None,
) -> bool:
    specification = execution_plan.specification
    return (
        _valid_sha256(current_source_manifest_sha256)
        and current_source_manifest_sha256
        == specification.plan.source_manifest_sha256
        and _valid_image_digest(current_runtime_image_digest)
        and current_runtime_image_digest
        == specification.plan.runtime_image_digest
        and type(current_vulnerable_target)
        is WebImpactApprovedTarget
        and current_vulnerable_target
        == specification.vulnerable_target
        and (
            (
                specification.control_target is None
                and current_control_target is None
            )
            or (
                specification.control_target is not None
                and type(current_control_target)
                is WebImpactApprovedTarget
                and current_control_target
                == specification.control_target
            )
        )
    )


def _preissued_plan_is_canonical(
    execution_plan: WebImpactExecutionPlan,
) -> bool:
    specification = execution_plan.specification
    if (
        type(specification) is not WebImpactExecutionSpecification
        or type(specification.plan) is not WebImpactPlan
        or not _valid_sha256(specification.operator_spec_sha256)
        or type(specification.operator_spec_size_bytes) is not int
        or not 1
        <= specification.operator_spec_size_bytes
        <= WEB_IMPACT_OPERATOR_SPEC_MAX_BYTES
        or type(specification.vulnerable_target)
        is not WebImpactApprovedTarget
        or specification.vulnerable_target.binding_sha256
        != specification.plan.authorized_target_binding_sha256
        or specification.vulnerable_target.generation
        != specification.plan.target_generation
        or (
            specification.plan.differential is None
            and specification.control_target is not None
        )
        or (
            specification.plan.differential is not None
            and (
                type(specification.control_target)
                is not WebImpactApprovedTarget
                or specification.control_target.binding_sha256
                != specification.plan.differential.control_target_binding_sha256
                or specification.control_target.generation
                != specification.plan.differential.control_target_generation
            )
        )
    ):
        return False
    try:
        rebuilt_plan = build_web_impact_plan(
            source_manifest_sha256=(
                specification.plan.source_manifest_sha256
            ),
            runtime_image_digest=specification.plan.runtime_image_digest,
            authorized_target_binding_sha256=(
                specification.plan.authorized_target_binding_sha256
            ),
            target_generation=specification.plan.target_generation,
            identities=specification.plan.identities,
            timeline=specification.plan.timeline,
            source_sink=specification.plan.source_sink,
            oracle=specification.plan.oracle,
            differential=specification.plan.differential,
        )
    except (AttributeError, TypeError, ValueError, WebImpactPreflightError):
        return False
    if rebuilt_plan != specification.plan:
        return False
    expected_count = WEB_IMPACT_REPLAY_COUNT * (
        2 if specification.control_target is not None else 1
    )
    if (
        type(execution_plan.requests) is not tuple
        or len(execution_plan.requests) != expected_count
    ):
        return False
    request_ids: set[str] = set()
    run_ids: set[str] = set()
    nonce_hashes: set[str] = set()
    request_hashes: set[str] = set()
    transport_hashes: set[str] = set()
    for position, request in enumerate(
        execution_plan.requests,
        start=1,
    ):
        if type(request) is not WebImpactReplayRequest:
            return False
        control = position > WEB_IMPACT_REPLAY_COUNT
        expected_kind = "control" if control else "vulnerable"
        expected_ordinal = (
            position - WEB_IMPACT_REPLAY_COUNT
            if control
            else position
        )
        target = (
            specification.control_target
            if control
            else specification.vulnerable_target
        )
        if (
            target is None
            or not _valid_id(request.request_id)
            or not _valid_id(request.run_id)
            or request.request_id == request.run_id
            or request.request_id in request_ids
            or request.run_id in run_ids
            or request.request_id in run_ids
            or request.run_id in request_ids
            or not _valid_sha256(request.replay_nonce_sha256)
            or request.replay_nonce_sha256 in nonce_hashes
            or request.replay_target_kind != expected_kind
            or request.replay_ordinal != expected_ordinal
            or request.operator_spec_sha256
            != specification.operator_spec_sha256
            or request.plan_sha256 != specification.plan.plan_sha256
            or request.source_manifest_sha256
            != specification.plan.source_manifest_sha256
            or request.runtime_image_digest
            != specification.plan.runtime_image_digest
            or request.target != target
        ):
            return False
        try:
            expected_epoch = web_identity_epoch_sha256(
                specification.plan,
                request.replay_nonce_sha256,
            )
            expected_semantic = web_replay_execution_contract_sha256(
                specification.plan,
                target_kind=expected_kind,
                replay_ordinal=expected_ordinal,
                replay_nonce_sha256=request.replay_nonce_sha256,
            )
            expected_transport = _transport_execution_contract_sha256(
                specification,
                request_id=request.request_id,
                run_id=request.run_id,
                replay_target_kind=expected_kind,
                replay_ordinal=expected_ordinal,
                replay_nonce_sha256=request.replay_nonce_sha256,
                identity_epoch_sha256=expected_epoch,
                semantic_execution_contract_sha256=expected_semantic,
                target=target,
            )
            request_hash = request.request_sha256
        except (AttributeError, TypeError, ValueError):
            return False
        if (
            request.identity_epoch_sha256 != expected_epoch
            or request.semantic_execution_contract_sha256
            != expected_semantic
            or request.transport_execution_contract_sha256
            != expected_transport
            or request_hash in request_hashes
            or expected_transport in transport_hashes
        ):
            return False
        request_ids.add(request.request_id)
        run_ids.add(request.run_id)
        nonce_hashes.add(request.replay_nonce_sha256)
        request_hashes.add(request_hash)
        transport_hashes.add(expected_transport)
    try:
        execution_plan.canonical_bytes
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _semantic_observation_matches(
    request: WebImpactReplayRequest,
    receipt: WebImpactExecutionReceipt,
    observation: WebImpactReplayObservation,
) -> bool:
    return (
        type(observation) is WebImpactReplayObservation
        and observation.target_kind == request.replay_target_kind
        and observation.replay_ordinal == request.replay_ordinal
        and observation.run_id == request.run_id
        and observation.receipt_id == receipt.receipt_id
        and observation.receipt_sha256 == receipt.sha256
        and observation.replay_nonce_sha256
        == request.replay_nonce_sha256
        and observation.identity_epoch_sha256
        == request.identity_epoch_sha256
        and observation.execution_contract_sha256
        == request.semantic_execution_contract_sha256
        and observation.plan_sha256 == request.plan_sha256
        and observation.source_manifest_sha256
        == request.source_manifest_sha256
        and observation.runtime_image_digest
        == request.runtime_image_digest
        and observation.authorized_target_binding_sha256
        == request.target.binding_sha256
        and observation.target_generation == request.target.generation
        and observation.clean_workspace == receipt.clean_workspace
        and observation.fresh_identity_state
        == receipt.fresh_identity_state
        and observation.network_target_authorized
        == receipt.network_target_authorized
        and observation.orchestration_status
        == receipt.orchestration_status
        and observation.exit_code == receipt.exit_code
        and observation.timed_out == receipt.timed_out
        and observation.capture_complete == receipt.capture_complete
        and observation.truncation_known == receipt.truncation_known
        and observation.truncated == receipt.truncated
        and (
            (observation.capture_error is None)
            == (receipt.capture_error_code is None)
        )
        and web_impact_observation_commitment_sha256(observation)
        == receipt.observation_commitment_sha256
        and web_impact_artifact_manifest_sha256(observation)
        == receipt.artifact_manifest_sha256
    )


def _receipt_matches_request(
    request: WebImpactReplayRequest,
    receipt: WebImpactExecutionReceipt,
) -> bool:
    return (
        receipt.request_id == request.request_id
        and receipt.run_id == request.run_id
        and receipt.request_sha256 == request.request_sha256
        and receipt.replay_target_kind == request.replay_target_kind
        and receipt.replay_ordinal == request.replay_ordinal
        and receipt.replay_nonce_sha256
        == request.replay_nonce_sha256
        and receipt.identity_epoch_sha256
        == request.identity_epoch_sha256
        and receipt.semantic_execution_contract_sha256
        == request.semantic_execution_contract_sha256
        and receipt.transport_execution_contract_sha256
        == request.transport_execution_contract_sha256
        and receipt.operator_spec_sha256
        == request.operator_spec_sha256
        and receipt.plan_sha256 == request.plan_sha256
        and receipt.target == request.target
    )


def _transport_succeeded(receipt: WebImpactExecutionReceipt) -> bool:
    return (
        receipt.orchestration_status == "completed"
        and type(receipt.exit_code) is int
        and receipt.exit_code == 0
        and receipt.timed_out is False
        and receipt.clean_workspace is True
        and receipt.fresh_identity_state is True
        and receipt.network_target_authorized is True
        and receipt.capture_complete is True
        and receipt.truncation_known is True
        and receipt.truncated is False
        and receipt.capture_error_code is None
    )


def evaluate_web_impact_execution(
    execution_plan: WebImpactExecutionPlan,
    transports: Iterable[WebImpactReplayTransportObservation],
    *,
    operator_spec_payload: bytes,
    current_source_manifest_sha256: str,
    current_runtime_image_digest: str,
    current_vulnerable_target: WebImpactApprovedTarget,
    current_control_target: WebImpactApprovedTarget | None = None,
) -> WebImpactExecutionEvaluation:
    """Verify exact transport evidence, then reuse the Web semantic oracle."""

    if (
        type(execution_plan) is not WebImpactExecutionPlan
        or not _preissued_plan_is_canonical(execution_plan)
    ):
        return _rejected("execution_plan_invalid")
    if not _current_bindings_match(
        execution_plan,
        current_source_manifest_sha256=current_source_manifest_sha256,
        current_runtime_image_digest=current_runtime_image_digest,
        current_vulnerable_target=current_vulnerable_target,
        current_control_target=current_control_target,
    ):
        return _rejected(
            "current_binding_mismatch",
            execution_plan=execution_plan,
        )
    try:
        reparsed_specification = parse_web_impact_operator_spec(
            operator_spec_payload,
            current_source_manifest_sha256=(
                current_source_manifest_sha256
            ),
            current_runtime_image_digest=current_runtime_image_digest,
            current_vulnerable_target=current_vulnerable_target,
            current_control_target=current_control_target,
        )
    except (TypeError, ValueError, WebImpactExecutionPreflightError):
        return _rejected(
            "operator_spec_revalidation_failed",
            execution_plan=execution_plan,
        )
    if reparsed_specification != execution_plan.specification:
        return _rejected(
            "operator_spec_rebinding_detected",
            execution_plan=execution_plan,
        )
    expected_count = len(execution_plan.requests)
    try:
        values = tuple(islice(iter(transports), expected_count + 1))
    except Exception:
        return _rejected(
            "transports_not_iterable",
            execution_plan=execution_plan,
        )
    if len(values) != expected_count:
        return _rejected(
            "transport_count_mismatch",
            execution_plan=execution_plan,
        )

    run_ids: set[str] = set()
    receipt_ids: set[str] = set()
    receipt_hashes: set[str] = set()
    artifact_ids: set[str] = {
        identifier
        for request in execution_plan.requests
        for identifier in (request.request_id, request.run_id)
    }
    total_capture_bytes = 0
    semantic_observations: list[WebImpactReplayObservation] = []
    records: list[WebImpactExecutionRecord] = []
    for position, (request, raw) in enumerate(
        zip(execution_plan.requests, values, strict=True),
        start=1,
    ):
        prefix = f"replay-{position}:"
        if type(raw) is not WebImpactReplayTransportObservation:
            return _rejected(
                prefix + "transport_type_invalid",
                execution_plan=execution_plan,
                records=tuple(records),
            )
        if (
            type(raw.request_payload) is not bytes
            or not raw.request_payload
            or len(raw.request_payload)
            > WEB_IMPACT_EXECUTION_REQUEST_MAX_BYTES
            or raw.request_payload != request.canonical_bytes
            or _sha256(raw.request_payload) != request.request_sha256
        ):
            return _rejected(
                prefix + "issued_request_mismatch",
                execution_plan=execution_plan,
                records=tuple(records),
            )
        try:
            receipt = WebImpactExecutionReceipt.from_payload(
                raw.receipt_payload
            )
        except (TypeError, ValueError):
            return _rejected(
                prefix + "receipt_document_invalid",
                execution_plan=execution_plan,
                records=tuple(records),
            )
        if not _receipt_matches_request(request, receipt):
            return _rejected(
                prefix + "receipt_request_binding_mismatch",
                execution_plan=execution_plan,
                records=tuple(records),
            )
        if not _transport_succeeded(receipt):
            return _rejected(
                prefix + "transport_not_clean_success",
                execution_plan=execution_plan,
                records=tuple(records),
            )
        if (
            request.run_id in run_ids
            or receipt.receipt_id in receipt_ids
            or receipt.sha256 in receipt_hashes
            or receipt.receipt_id in artifact_ids
        ):
            return _rejected(
                prefix + "duplicate_run_or_receipt",
                execution_plan=execution_plan,
                records=tuple(records),
            )
        run_ids.add(request.run_id)
        receipt_ids.add(receipt.receipt_id)
        receipt_hashes.add(receipt.sha256)
        artifact_ids.add(receipt.receipt_id)

        observation = raw.semantic_observation
        if not _observation_is_bounded(
            observation,
            expected_timeline_steps=len(
                execution_plan.specification.plan.timeline
            ),
        ):
            return _rejected(
                prefix + "semantic_observation_shape_invalid",
                execution_plan=execution_plan,
                records=tuple(records),
            )
        try:
            matches = _semantic_observation_matches(
                request,
                receipt,
                observation,
            )
        except (AttributeError, TypeError, ValueError):
            matches = False
        if not matches:
            return _rejected(
                prefix + "semantic_transport_binding_mismatch",
                execution_plan=execution_plan,
                records=tuple(records),
            )
        error, consumed = _validate_captured_artifacts(
            observation,
            raw.artifacts,
            used_artifact_ids=artifact_ids,
        )
        if error is not None:
            return _rejected(
                prefix + error,
                execution_plan=execution_plan,
                records=tuple(records),
            )
        total_capture_bytes += consumed
        if total_capture_bytes > WEB_IMPACT_EXECUTION_MAX_CAPTURE_BYTES:
            return _rejected(
                "capture_total_size_exceeded",
                execution_plan=execution_plan,
                records=tuple(records),
            )
        semantic_observations.append(observation)
        records.append(
            WebImpactExecutionRecord(
                replay_target_kind=request.replay_target_kind,
                replay_ordinal=request.replay_ordinal,
                request_id=request.request_id,
                request_sha256=request.request_sha256,
                run_id=request.run_id,
                receipt_id=receipt.receipt_id,
                receipt_sha256=receipt.sha256,
                replay_nonce_sha256=request.replay_nonce_sha256,
                semantic_execution_contract_sha256=(
                    request.semantic_execution_contract_sha256
                ),
                transport_execution_contract_sha256=(
                    request.transport_execution_contract_sha256
                ),
                observation_commitment_sha256=(
                    receipt.observation_commitment_sha256
                ),
                artifact_manifest_sha256=(
                    receipt.artifact_manifest_sha256
                ),
                target=request.target,
            )
        )

    semantic = evaluate_web_impact(
        execution_plan.specification.plan,
        tuple(semantic_observations),
    )
    if not semantic.passed:
        return _rejected(
            "semantic_evaluation_rejected",
            execution_plan=execution_plan,
            records=tuple(records),
            semantic=semantic,
        )
    result = WebImpactExecutionEvaluation(
        verdict=WebImpactExecutionVerdict.CONFIRMED,
        reason_codes=(),
        execution_plan_sha256=execution_plan.execution_plan_sha256,
        records=tuple(records),
        semantic_evaluation=semantic,
    )
    try:
        result.canonical_bytes
    except ValueError:
        return _rejected(
            "execution_evaluation_size_exceeded",
            execution_plan=execution_plan,
        )
    return result


__all__ = [
    "WEB_IMPACT_ALLOWLISTED_TARGET_KIND",
    "WEB_IMPACT_EXECUTION_EVALUATION_MAX_BYTES",
    "WEB_IMPACT_EXECUTION_MAX_CAPTURE_BYTES",
    "WEB_IMPACT_EXECUTION_PLAN_MAX_BYTES",
    "WEB_IMPACT_EXECUTION_PROTOCOL",
    "WEB_IMPACT_EXECUTION_RECEIPT_MAX_BYTES",
    "WEB_IMPACT_EXECUTION_REQUEST_MAX_BYTES",
    "WEB_IMPACT_OPERATOR_SPEC_MAX_BYTES",
    "WEB_IMPACT_OPERATOR_SPEC_PROTOCOL",
    "WEB_IMPACT_REPLAY_NONCE_MAX_BYTES",
    "WEB_IMPACT_REPLAY_NONCE_MIN_BYTES",
    "WebImpactApprovedTarget",
    "WebImpactCapturedArtifact",
    "WebImpactExecutionEvaluation",
    "WebImpactExecutionPlan",
    "WebImpactExecutionPreflightError",
    "WebImpactExecutionReceipt",
    "WebImpactExecutionRecord",
    "WebImpactExecutionSpecification",
    "WebImpactExecutionVerdict",
    "WebImpactReplayIssue",
    "WebImpactReplayRequest",
    "WebImpactReplayTransportObservation",
    "build_web_impact_execution_receipt",
    "evaluate_web_impact_execution",
    "parse_web_impact_operator_spec",
    "plan_web_impact_execution",
    "web_impact_artifact_manifest_sha256",
    "web_impact_observation_commitment_sha256",
]
