"""Pure contract for candidate-free Rev accepted-input verification.

The contract is deliberately value-free.  An operator supplies exact hashes
and sizes for the original binary's accepted and rejected observations.  The
engine owns the fixed three-positive/three-mutated-control plan and records
only hashes, sizes, exit codes, and durable pointers.  Input and output bytes
never enter ``state.json`` and this contract cannot authorize a flag candidate,
submission, or challenge status transition.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Mapping, Sequence


REV_ACCEPTANCE_PROTOCOL = "ctfos.rev.accepted-input.v1"
REV_ACCEPTANCE_OPERATOR_SPEC_PROTOCOL = (
    "ctfos.rev.accepted-input.operator-spec.v1"
)
REV_ACCEPTANCE_SCHEMA_VERSION = 1
REV_ACCEPTANCE_ATTEMPT_COUNT = 6
REV_ACCEPTANCE_MAX_INPUT_BYTES = 1024 * 1024
REV_ACCEPTANCE_MAX_SPEC_BYTES = 256 * 1024
REV_ACCEPTANCE_MAX_STREAM_BYTES = 16 * 1024 * 1024
REV_ACCEPTANCE_MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
REV_ACCEPTANCE_POSITIVE_IDS = (
    "accepted-repeat-1",
    "accepted-repeat-2",
    "accepted-repeat-3",
)
REV_ACCEPTANCE_CONTROL_IDS = (
    "xor-first-01",
    "xor-last-80",
    "truncate-last",
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_LOCATOR = re.compile(
    r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))(?!.*//)[^\\\x00]{1,4096}$"
)
_SPEC_KEYS = frozenset(
    {
        "accepted",
        "accepted_input_locator",
        "controls",
        "protocol",
        "schema_version",
        "source_locator",
    }
)
_EXPECTATION_KEYS = frozenset(
    {
        "exit_code",
        "stderr_sha256",
        "stderr_size_bytes",
        "stdout_sha256",
        "stdout_size_bytes",
    }
)
_CONTROL_KEYS = frozenset({"expectation", "mutation_id"})
_EXPECTED_ORACLE_KEYS = frozenset({"accepted", "controls"})
_OBSERVATION_KEYS = frozenset(
    {
        "capture_complete",
        "clean_workspace",
        "exit_code",
        "input_sha256",
        "input_size_bytes",
        "mutation_id",
        "network",
        "ordinal",
        "phase",
        "receipt_id",
        "run_id",
        "stderr_artifact_id",
        "stderr_sha256",
        "stderr_size_bytes",
        "stdout_artifact_id",
        "stdout_sha256",
        "stdout_size_bytes",
        "timed_out",
    }
)
_EVALUATION_KEYS = frozenset(
    {
        "authorities",
        "image_digest",
        "observations",
        "operator_spec_sha256",
        "passed",
        "plan_sha256",
        "protocol",
        "reason_codes",
        "schema_version",
        "source_manifest_sha256",
        "source_sha256",
        "source_size_bytes",
    }
)
_AUTHORITIES = {
    "automatic_submission_authorized": False,
    "candidate_authorized": False,
    "challenge_status_transition_authorized": False,
    "flag_proven": False,
}


class RevAcceptanceContractError(ValueError):
    """The strict accepted-input contract is not canonical."""


def canonical_json_bytes(value: object) -> bytes:
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
        raise RevAcceptanceContractError("canonical_json_invalid") from error
    if len(payload) > REV_ACCEPTANCE_MAX_EVIDENCE_BYTES:
        raise RevAcceptanceContractError("canonical_json_too_large")
    return payload


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _exact_dict(
    value: object,
    keys: frozenset[str],
    code: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise RevAcceptanceContractError(code)
    return value


def _safe_locator(value: object) -> str:
    if (
        type(value) is not str
        or _SAFE_LOCATOR.fullmatch(value) is None
        or value.endswith("/")
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise RevAcceptanceContractError("locator_invalid")
    return value


def _bounded_int(
    value: object,
    *,
    minimum: int,
    maximum: int,
    code: str,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise RevAcceptanceContractError(code)
    return value


@dataclass(frozen=True, slots=True)
class RevAcceptanceExpectation:
    exit_code: int
    stdout_sha256: str
    stdout_size_bytes: int
    stderr_sha256: str
    stderr_size_bytes: int

    @classmethod
    def from_mapping(
        cls,
        value: object,
    ) -> "RevAcceptanceExpectation":
        item = _exact_dict(
            value,
            _EXPECTATION_KEYS,
            "expectation_schema_invalid",
        )
        hashes = (item["stdout_sha256"], item["stderr_sha256"])
        if any(
            type(digest) is not str or _SHA256.fullmatch(digest) is None
            for digest in hashes
        ):
            raise RevAcceptanceContractError("expectation_hash_invalid")
        return cls(
            exit_code=_bounded_int(
                item["exit_code"],
                minimum=0,
                maximum=255,
                code="expectation_exit_invalid",
            ),
            stdout_sha256=item["stdout_sha256"],
            stdout_size_bytes=_bounded_int(
                item["stdout_size_bytes"],
                minimum=0,
                maximum=REV_ACCEPTANCE_MAX_STREAM_BYTES,
                code="expectation_size_invalid",
            ),
            stderr_sha256=item["stderr_sha256"],
            stderr_size_bytes=_bounded_int(
                item["stderr_size_bytes"],
                minimum=0,
                maximum=REV_ACCEPTANCE_MAX_STREAM_BYTES,
                code="expectation_size_invalid",
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "exit_code": self.exit_code,
            "stderr_sha256": self.stderr_sha256,
            "stderr_size_bytes": self.stderr_size_bytes,
            "stdout_sha256": self.stdout_sha256,
            "stdout_size_bytes": self.stdout_size_bytes,
        }

    def matches(self, observation: Mapping[str, object]) -> bool:
        return (
            observation.get("exit_code") == self.exit_code
            and observation.get("stdout_sha256") == self.stdout_sha256
            and observation.get("stdout_size_bytes")
            == self.stdout_size_bytes
            and observation.get("stderr_sha256") == self.stderr_sha256
            and observation.get("stderr_size_bytes")
            == self.stderr_size_bytes
        )


@dataclass(frozen=True, slots=True)
class RevAcceptanceOperatorSpec:
    source_locator: str
    accepted_input_locator: str
    accepted: RevAcceptanceExpectation
    controls: tuple[
        tuple[str, RevAcceptanceExpectation],
        ...,
    ]

    @classmethod
    def from_mapping(
        cls,
        value: object,
    ) -> "RevAcceptanceOperatorSpec":
        item = _exact_dict(value, _SPEC_KEYS, "spec_schema_invalid")
        if (
            item["schema_version"] != REV_ACCEPTANCE_SCHEMA_VERSION
            or item["protocol"] != REV_ACCEPTANCE_OPERATOR_SPEC_PROTOCOL
        ):
            raise RevAcceptanceContractError("spec_protocol_invalid")
        raw_controls = item["controls"]
        if type(raw_controls) is not list or len(raw_controls) != 3:
            raise RevAcceptanceContractError("controls_invalid")
        controls: list[tuple[str, RevAcceptanceExpectation]] = []
        for index, raw in enumerate(raw_controls):
            control = _exact_dict(
                raw,
                _CONTROL_KEYS,
                "control_schema_invalid",
            )
            mutation_id = control["mutation_id"]
            if mutation_id != REV_ACCEPTANCE_CONTROL_IDS[index]:
                raise RevAcceptanceContractError("control_order_invalid")
            controls.append(
                (
                    mutation_id,
                    RevAcceptanceExpectation.from_mapping(
                        control["expectation"]
                    ),
                )
            )
        spec = cls(
            source_locator=_safe_locator(item["source_locator"]),
            accepted_input_locator=_safe_locator(
                item["accepted_input_locator"]
            ),
            accepted=RevAcceptanceExpectation.from_mapping(
                item["accepted"]
            ),
            controls=tuple(controls),
        )
        if any(
            expectation == spec.accepted
            for _mutation_id, expectation in spec.controls
        ):
            raise RevAcceptanceContractError(
                "control_does_not_reject"
            )
        if len(canonical_json_bytes(spec.to_dict())) > REV_ACCEPTANCE_MAX_SPEC_BYTES:
            raise RevAcceptanceContractError("spec_too_large")
        return spec

    def to_dict(self) -> dict[str, object]:
        return {
            "accepted": self.accepted.to_dict(),
            "accepted_input_locator": self.accepted_input_locator,
            "controls": [
                {
                    "expectation": expectation.to_dict(),
                    "mutation_id": mutation_id,
                }
                for mutation_id, expectation in self.controls
            ],
            "protocol": REV_ACCEPTANCE_OPERATOR_SPEC_PROTOCOL,
            "schema_version": REV_ACCEPTANCE_SCHEMA_VERSION,
            "source_locator": self.source_locator,
        }

    @property
    def evidence_sha256(self) -> str:
        return sha256(canonical_json_bytes(self.to_dict()))

    @property
    def expected_oracle(self) -> dict[str, object]:
        """Return the value-free oracle projection safe for managed state."""

        return {
            "accepted": self.accepted.to_dict(),
            "controls": [
                {
                    "expectation": expectation.to_dict(),
                    "mutation_id": mutation_id,
                }
                for mutation_id, expectation in self.controls
            ],
        }


def validate_rev_acceptance_expected_oracle(
    value: object,
) -> dict[str, object]:
    """Validate the exact hash/size-only oracle exposed to a Builder."""

    item = _exact_dict(
        value,
        _EXPECTED_ORACLE_KEYS,
        "expected_oracle_schema_invalid",
    )
    accepted = RevAcceptanceExpectation.from_mapping(item["accepted"])
    raw_controls = item["controls"]
    if type(raw_controls) is not list or len(raw_controls) != 3:
        raise RevAcceptanceContractError(
            "expected_oracle_controls_invalid"
        )
    controls: list[dict[str, object]] = []
    for index, raw in enumerate(raw_controls):
        control = _exact_dict(
            raw,
            _CONTROL_KEYS,
            "expected_oracle_control_schema_invalid",
        )
        mutation_id = control["mutation_id"]
        if mutation_id != REV_ACCEPTANCE_CONTROL_IDS[index]:
            raise RevAcceptanceContractError(
                "expected_oracle_control_order_invalid"
            )
        expectation = RevAcceptanceExpectation.from_mapping(
            control["expectation"]
        )
        if expectation == accepted:
            raise RevAcceptanceContractError(
                "expected_oracle_control_does_not_reject"
            )
        controls.append(
            {
                "expectation": expectation.to_dict(),
                "mutation_id": mutation_id,
            }
        )
    normalized = {
        "accepted": accepted.to_dict(),
        "controls": controls,
    }
    canonical_json_bytes(normalized)
    return normalized


@dataclass(frozen=True, slots=True)
class RevAcceptanceAttempt:
    ordinal: int
    phase: str
    mutation_id: str
    payload: bytes

    @property
    def input_sha256(self) -> str:
        return sha256(self.payload)

    def to_dict(self) -> dict[str, object]:
        return {
            "input_sha256": self.input_sha256,
            "input_size_bytes": len(self.payload),
            "mutation_id": self.mutation_id,
            "ordinal": self.ordinal,
            "phase": self.phase,
        }


def build_rev_acceptance_plan(
    accepted_input: bytes,
) -> tuple[RevAcceptanceAttempt, ...]:
    if type(accepted_input) is not bytes:
        raise RevAcceptanceContractError("accepted_input_type_invalid")
    if len(accepted_input) > REV_ACCEPTANCE_MAX_INPUT_BYTES:
        raise RevAcceptanceContractError("accepted_input_too_large")
    positives = tuple(
        RevAcceptanceAttempt(index, "positive", mutation_id, accepted_input)
        for index, mutation_id in enumerate(
            REV_ACCEPTANCE_POSITIVE_IDS,
            start=1,
        )
    )
    if accepted_input:
        controls = (
            bytes((accepted_input[0] ^ 0x01,)) + accepted_input[1:],
            accepted_input[:-1]
            + bytes((accepted_input[-1] ^ 0x80,)),
            accepted_input[:-1],
        )
    else:
        controls = (b"\x00", b"\x0a", b"\xff")
    negatives = tuple(
        RevAcceptanceAttempt(
            index,
            "control",
            mutation_id,
            payload,
        )
        for index, (mutation_id, payload) in enumerate(
            zip(
                REV_ACCEPTANCE_CONTROL_IDS,
                controls,
                strict=True,
            ),
            start=4,
        )
    )
    plan = (*positives, *negatives)
    if (
        len(plan) != REV_ACCEPTANCE_ATTEMPT_COUNT
        or len({item.input_sha256 for item in negatives}) != 3
        or any(item.payload == accepted_input for item in negatives)
    ):
        raise RevAcceptanceContractError("mutation_plan_invalid")
    return plan


def rev_acceptance_plan_sha256(
    plan: Sequence[RevAcceptanceAttempt],
) -> str:
    return sha256(canonical_json_bytes([item.to_dict() for item in plan]))


def _validate_observation_shape(
    value: object,
) -> dict[str, object]:
    item = _exact_dict(
        value,
        _OBSERVATION_KEYS,
        "observation_schema_invalid",
    )
    identifier_fields = (
        "run_id",
        "receipt_id",
        "stdout_artifact_id",
        "stderr_artifact_id",
    )
    if any(
        type(item[field]) is not str
        or not item[field]
        or len(item[field].encode("utf-8")) > 1024
        for field in identifier_fields
    ):
        raise RevAcceptanceContractError("observation_id_invalid")
    if (
        type(item["ordinal"]) is not int
        or not 1 <= item["ordinal"] <= REV_ACCEPTANCE_ATTEMPT_COUNT
        or type(item["phase"]) is not str
        or type(item["mutation_id"]) is not str
        or type(item["input_sha256"]) is not str
        or _SHA256.fullmatch(item["input_sha256"]) is None
        or type(item["input_size_bytes"]) is not int
        or not (
            0
            <= item["input_size_bytes"]
            <= REV_ACCEPTANCE_MAX_INPUT_BYTES
        )
        or item["network"] != "none"
        or type(item["clean_workspace"]) is not bool
        or type(item["capture_complete"]) is not bool
        or type(item["timed_out"]) is not bool
        or type(item["exit_code"]) is not int
        or not 0 <= item["exit_code"] <= 255
    ):
        raise RevAcceptanceContractError("observation_binding_invalid")
    for stream in ("stdout", "stderr"):
        digest = item[f"{stream}_sha256"]
        size = item[f"{stream}_size_bytes"]
        if (
            type(digest) is not str
            or _SHA256.fullmatch(digest) is None
            or type(size) is not int
            or not 0 <= size <= REV_ACCEPTANCE_MAX_STREAM_BYTES
        ):
            raise RevAcceptanceContractError(
                "observation_stream_invalid"
            )
    return item


def _validate_observation(
    value: object,
    planned: RevAcceptanceAttempt,
) -> dict[str, object]:
    item = _validate_observation_shape(value)
    if (
        item["ordinal"] != planned.ordinal
        or item["phase"] != planned.phase
        or item["mutation_id"] != planned.mutation_id
        or item["input_sha256"] != planned.input_sha256
        or item["input_size_bytes"] != len(planned.payload)
    ):
        raise RevAcceptanceContractError("observation_binding_invalid")
    return item


def evaluate_rev_acceptance(
    *,
    spec: RevAcceptanceOperatorSpec,
    plan: Sequence[RevAcceptanceAttempt],
    observations: Sequence[Mapping[str, object]],
    source_manifest_sha256: str,
    source_sha256: str,
    source_size_bytes: int,
    image_digest: str,
) -> dict[str, object]:
    if (
        len(plan) != REV_ACCEPTANCE_ATTEMPT_COUNT
        or len(observations) != REV_ACCEPTANCE_ATTEMPT_COUNT
        or type(source_manifest_sha256) is not str
        or _SHA256.fullmatch(source_manifest_sha256) is None
        or type(source_sha256) is not str
        or _SHA256.fullmatch(source_sha256) is None
        or type(source_size_bytes) is not int
        or source_size_bytes <= 0
        or type(image_digest) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest) is None
    ):
        raise RevAcceptanceContractError("evaluation_binding_invalid")
    normalized = [
        _validate_observation(observation, planned)
        for observation, planned in zip(
            observations,
            plan,
            strict=True,
        )
    ]
    reason_codes: list[str] = []
    run_ids: set[str] = set()
    receipt_ids: set[str] = set()
    artifact_ids: set[str] = set()
    for index, observation in enumerate(normalized):
        if (
            observation["run_id"] in run_ids
            or observation["receipt_id"] in receipt_ids
            or observation["stdout_artifact_id"] in artifact_ids
            or observation["stderr_artifact_id"] in artifact_ids
            or observation["stdout_artifact_id"]
            == observation["stderr_artifact_id"]
        ):
            reason_codes.append("identity_reused")
        run_ids.add(observation["run_id"])
        receipt_ids.add(observation["receipt_id"])
        artifact_ids.update(
            (
                observation["stdout_artifact_id"],
                observation["stderr_artifact_id"],
            )
        )
        if (
            observation["clean_workspace"] is not True
            or observation["capture_complete"] is not True
            or observation["timed_out"] is not False
        ):
            reason_codes.append(
                f"attempt_{index + 1}_transport_incomplete"
            )
        expectation = (
            spec.accepted
            if index < 3
            else spec.controls[index - 3][1]
        )
        if not expectation.matches(observation):
            reason_codes.append(f"attempt_{index + 1}_oracle_mismatch")
    evaluation = {
        "authorities": dict(_AUTHORITIES),
        "image_digest": image_digest,
        "observations": normalized,
        "operator_spec_sha256": spec.evidence_sha256,
        "passed": not reason_codes,
        "plan_sha256": rev_acceptance_plan_sha256(plan),
        "protocol": REV_ACCEPTANCE_PROTOCOL,
        "reason_codes": list(dict.fromkeys(reason_codes)),
        "schema_version": REV_ACCEPTANCE_SCHEMA_VERSION,
        "source_manifest_sha256": source_manifest_sha256,
        "source_sha256": source_sha256,
        "source_size_bytes": source_size_bytes,
    }
    canonical_json_bytes(evaluation)
    return evaluation


def validate_rev_acceptance_evaluation(
    value: object,
) -> dict[str, object]:
    item = _exact_dict(
        value,
        _EVALUATION_KEYS,
        "evaluation_schema_invalid",
    )
    if (
        item["protocol"] != REV_ACCEPTANCE_PROTOCOL
        or item["schema_version"] != REV_ACCEPTANCE_SCHEMA_VERSION
        or item["authorities"] != _AUTHORITIES
        or type(item["passed"]) is not bool
        or type(item["reason_codes"]) is not list
        or any(type(code) is not str or not code for code in item["reason_codes"])
        or type(item["observations"]) is not list
        or len(item["observations"]) != REV_ACCEPTANCE_ATTEMPT_COUNT
        or any(
            type(item[field]) is not str
            or (
                re.fullmatch(r"sha256:[0-9a-f]{64}", item[field]) is None
                if field == "image_digest"
                else _SHA256.fullmatch(item[field]) is None
            )
            for field in (
                "image_digest",
                "operator_spec_sha256",
                "plan_sha256",
                "source_manifest_sha256",
                "source_sha256",
            )
        )
        or type(item["source_size_bytes"]) is not int
        or item["source_size_bytes"] <= 0
        or item["passed"] is not (not item["reason_codes"])
    ):
        raise RevAcceptanceContractError("evaluation_invalid")
    observations = [
        _validate_observation_shape(observation)
        for observation in item["observations"]
    ]
    mutation_ids = (
        *REV_ACCEPTANCE_POSITIVE_IDS,
        *REV_ACCEPTANCE_CONTROL_IDS,
    )
    if any(
        observation["ordinal"] != index
        or observation["phase"]
        != ("positive" if index <= 3 else "control")
        or observation["mutation_id"] != mutation_ids[index - 1]
        for index, observation in enumerate(observations, start=1)
    ):
        raise RevAcceptanceContractError(
            "evaluation_observation_order_invalid"
        )
    canonical_json_bytes(item)
    return item


__all__ = [
    "REV_ACCEPTANCE_ATTEMPT_COUNT",
    "REV_ACCEPTANCE_CONTROL_IDS",
    "REV_ACCEPTANCE_MAX_EVIDENCE_BYTES",
    "REV_ACCEPTANCE_MAX_INPUT_BYTES",
    "REV_ACCEPTANCE_MAX_SPEC_BYTES",
    "REV_ACCEPTANCE_MAX_STREAM_BYTES",
    "REV_ACCEPTANCE_OPERATOR_SPEC_PROTOCOL",
    "REV_ACCEPTANCE_POSITIVE_IDS",
    "REV_ACCEPTANCE_PROTOCOL",
    "REV_ACCEPTANCE_SCHEMA_VERSION",
    "RevAcceptanceAttempt",
    "RevAcceptanceContractError",
    "RevAcceptanceExpectation",
    "RevAcceptanceOperatorSpec",
    "build_rev_acceptance_plan",
    "canonical_json_bytes",
    "evaluate_rev_acceptance",
    "rev_acceptance_plan_sha256",
    "sha256",
    "validate_rev_acceptance_expected_oracle",
    "validate_rev_acceptance_evaluation",
]
