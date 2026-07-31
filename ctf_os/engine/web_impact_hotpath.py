"""Operator-explicit, temporally pre-issued Web impact execution.

This is the stateful bridge between the pure Web transport/state contracts and
the challenge sandbox.  One call owns one already-open challenge only.  It
snapshots a strict operator specification and a value-free driver, commits all
request/run/receipt/capture identities before replay one, executes only the
image-owned HTTP/browser helpers, and appends the independently reconstructible
state graph in one final compare-and-swap.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from ctf_os.director.resources import ResourceVector
from ctf_os.engine.web_impact import (
    WEB_IMPACT_MAX_ARTIFACT_BYTES,
    WEB_IMPACT_MAX_TRACE_BYTES,
    WebArtifactCommitment,
    WebImpactReplayObservation,
    WebSourceSinkObservation,
    WebTimelineEvent,
)
from ctf_os.engine.web_impact_driver import (
    WEB_IMPACT_DRIVER_MAX_BYTES,
    WebImpactDriverInput,
    WebImpactDriverManifest,
    parse_web_impact_driver_manifest,
    validate_route_payload,
    web_impact_target_binding_sha256,
    web_impact_trace_contract_sha256,
)
from ctf_os.engine.web_impact_execution import (
    WEB_IMPACT_EXECUTION_PROTOCOL,
    WEB_IMPACT_OPERATOR_SPEC_MAX_BYTES,
    WebImpactApprovedTarget,
    WebImpactCapturedArtifact,
    WebImpactExecutionEvaluation,
    WebImpactExecutionPlan,
    WebImpactExecutionPreflightError,
    WebImpactReplayIssue,
    WebImpactReplayTransportObservation,
    build_web_impact_execution_receipt,
    evaluate_web_impact_execution,
    parse_web_impact_operator_spec,
    plan_web_impact_execution,
)
from ctf_os.engine.web_impact_state import (
    WEB_IMPACT_STATE_PROTOCOL,
    WebImpactStateIds,
    WebImpactStateProjection,
    build_web_impact_state_projection,
    validate_web_impact_state_graph,
    validate_web_impact_state_projection,
)
from ctf_os.models import (
    ArtifactReference,
    ChallengeIdentity,
    ChallengeState,
    RunOrigin,
    TargetRecord,
    TargetStatus,
    utc_now,
)
from ctf_os.sandbox import (
    ChallengeScope,
    CommandSpec,
    NetworkPolicy,
    NetworkTarget,
)
from ctf_os.sandbox.files import (
    SafeFileError,
    copy_bounded_regular,
    ensure_private_directory,
    read_bounded_regular,
)
from ctf_os.sandbox.web_private import (
    private_web_identity_epoch_sha256,
    reset_private_web_identity_state,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.stages.ingest import inventory_challenge
from ctf_os.store.atomic import (
    StrictJSONError,
    atomic_write_bytes,
    atomic_write_json,
    strict_json_loads,
)

if TYPE_CHECKING:
    from ctf_os.engine.challenge import ChallengeEngine


WEB_IMPACT_HOTPATH_PROTOCOL = "ctfos.web.impact.hotpath.v1"
WEB_IMPACT_HOTPATH_SCHEMA_VERSION = 1
WEB_IMPACT_HOTPATH_MAX_ATTEMPTS = 64
WEB_IMPACT_HOTPATH_MAX_METADATA_BYTES = 4 * 1024 * 1024
WEB_IMPACT_HOTPATH_HELPER_MAX_RESPONSE_BYTES = (
    WEB_IMPACT_MAX_ARTIFACT_BYTES
)
_WEB_IMPACT_STATE_SAFE_ID = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,255}$"
)


class WebImpactHotPathError(RuntimeError):
    """An operator-visible failure before authority can be granted."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class _Snapshot:
    artifact_id: str
    path: str
    sha256: str
    size_bytes: int
    source_locator: str
    role: str

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "path": self.path,
            "role": self.role,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "source_locator": self.source_locator,
        }


@dataclass(frozen=True, slots=True)
class _ReplayIds:
    request_id: str
    run_id: str
    receipt_id: str
    request_artifact_ids: tuple[str, ...]
    response_artifact_ids: tuple[str, ...]
    trace_artifact_id: str

    def to_dict(self) -> dict[str, object]:
        return {
            "receipt_id": self.receipt_id,
            "request_artifact_ids": list(self.request_artifact_ids),
            "request_id": self.request_id,
            "response_artifact_ids": list(
                self.response_artifact_ids
            ),
            "run_id": self.run_id,
            "trace_artifact_id": self.trace_artifact_id,
        }


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
        raise WebImpactHotPathError("canonical_json_invalid") from error


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(16)}"


def _all_state_ids(state: ChallengeState) -> set[str]:
    values: set[str] = set()
    for collection in (
        state.goals,
        state.facts,
        state.hypotheses,
        state.experiments,
        state.progress_markers,
        state.candidates,
        state.submissions,
        state.artifacts,
        state.runs,
        state.receipts,
        state.sessions,
        state.cycles,
        state.waves,
        state.checkpoints,
        state.targets,
        state.workspace_publishes,
    ):
        values.update(
            item.id
            for item in collection
            if type(getattr(item, "id", None)) is str
        )
    return values


def _projection_reserved_ids(state: ChallengeState) -> set[str]:
    """Return IDs representable by the pure Web state contract.

    Existing target identifiers can contain URL punctuation.  Newly issued Web
    graph IDs are restricted to the contract-safe alphabet and therefore
    cannot collide with those legacy identifiers.
    """

    return {
        item
        for item in _all_state_ids(state)
        if _WEB_IMPACT_STATE_SAFE_ID.fullmatch(item) is not None
    }


def _target_for_id(
    engine: ChallengeEngine,
    state: ChallengeState,
    target_id: str,
) -> TargetRecord:
    target = next(
        (item for item in state.targets if item.id == target_id),
        None,
    )
    if (
        target is None
        or type(target) is not TargetRecord
        or target.status is not TargetStatus.ACTIVE
        or engine._target_is_expired(target)
        or target.enforcement not in {"proxy", "builtin"}
    ):
        raise WebImpactHotPathError(
            "web_impact_target_not_active_proxy_allowlisted"
        )
    parsed = NetworkTarget.parse(target.endpoint)
    if parsed.scheme not in {"http", "https"}:
        raise WebImpactHotPathError(
            "web_impact_target_must_be_http_origin"
        )
    return target


def _approved_target(target: TargetRecord) -> WebImpactApprovedTarget:
    return WebImpactApprovedTarget(
        kind="allowlisted_http_origin_v1",
        binding_sha256=web_impact_target_binding_sha256(target),
        generation=target.generation,
    )


def _read_snapshot(
    root: Path,
    snapshot: _Snapshot,
    *,
    maximum_bytes: int,
) -> bytes:
    try:
        payload = read_bounded_regular(
            root,
            snapshot.path,
            maximum_bytes=maximum_bytes,
            expected_sha256=snapshot.sha256,
            expected_size=snapshot.size_bytes,
        )
    except (OSError, SafeFileError, ValueError) as error:
        raise WebImpactHotPathError(
            "web_impact_snapshot_unavailable"
        ) from error
    if (
        len(payload) != snapshot.size_bytes
        or _sha256(payload) != snapshot.sha256
    ):
        raise WebImpactHotPathError(
            "web_impact_snapshot_binding_changed"
        )
    return payload


def _snapshot_workspace_input(
    engine: ChallengeEngine,
    state: ChallengeState,
    *,
    client: object,
    artifact_id: str,
    locator: str,
    destination: Path,
    role: str,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
) -> _Snapshot:
    try:
        immutable = engine._snapshot_workspace_file(
            state,
            client,
            locator,
            destination,
        )
    except Exception as error:
        raise WebImpactHotPathError(
            f"web_impact_{role}_snapshot_failed"
        ) from error
    if (
        expected_sha256 is not None
        and immutable.sha256 != expected_sha256
    ) or (
        expected_size is not None
        and immutable.size_bytes != expected_size
    ):
        raise WebImpactHotPathError(
            f"web_impact_{role}_snapshot_binding_mismatch"
        )
    paths = engine.store.challenge_paths(state.identity)
    return _Snapshot(
        artifact_id=artifact_id,
        path=immutable.path.relative_to(paths.root).as_posix(),
        sha256=immutable.sha256,
        size_bytes=immutable.size_bytes,
        source_locator=immutable.source_locator,
        role=role,
    )


def _snapshot_artifact_reference(
    snapshot: _Snapshot,
) -> ArtifactReference:
    return ArtifactReference(
        id=snapshot.artifact_id,
        path=snapshot.path,
        sha256=snapshot.sha256,
        size=snapshot.size_bytes,
        media_type=(
            "application/json"
            if snapshot.role in {"operator_spec", "driver"}
            else "application/octet-stream"
        ),
        extra={
            "context_visibility": "engine_private",
            "kind": f"web_impact_{snapshot.role}_snapshot",
            "protocol": WEB_IMPACT_HOTPATH_PROTOCOL,
            "source_locator": snapshot.source_locator,
        },
    )


def _strict_json_file(
    payload: bytes,
    *,
    maximum_bytes: int,
    code: str,
) -> dict[str, object]:
    try:
        value = strict_json_loads(
            payload,
            max_bytes=maximum_bytes,
            max_depth=20,
        )
    except (StrictJSONError, UnicodeError, ValueError) as error:
        raise WebImpactHotPathError(code) from error
    if type(value) is not dict:
        raise WebImpactHotPathError(code)
    return value


def _target_origin(target: TargetRecord) -> str:
    parsed = urlsplit(target.endpoint)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise WebImpactHotPathError(
            "web_impact_target_must_be_bare_origin"
        )
    return target.endpoint.rstrip("/")


def _request_capture_payload(
    *,
    request: object,
    step: object,
    target: WebImpactApprovedTarget,
) -> bytes:
    return _canonical_json_bytes(
        {
            "body": (
                {
                    "sha256": step.body.sha256,
                    "size_bytes": step.body.size_bytes,
                }
                if step.body is not None
                else None
            ),
            "channel": step.channel,
            "identity_epoch_sha256": (
                request.identity_epoch_sha256
            ),
            "method": step.method,
            "ordinal": step.ordinal,
            "protocol": WEB_IMPACT_HOTPATH_PROTOCOL,
            "request_shape_sha256": step.request_shape_sha256,
            "role": step.role,
            "route_binding_sha256": step.route_binding_sha256,
            "target": target.to_dict(),
            "transport_execution_contract_sha256": (
                request.transport_execution_contract_sha256
            ),
        }
    )


def _latest_timeline_event(
    payload: bytes,
    *,
    step: object,
) -> dict[str, object]:
    document = _strict_json_file(
        payload,
        maximum_bytes=WEB_IMPACT_HOTPATH_MAX_METADATA_BYTES,
        code="web_impact_timeline_invalid",
    )
    if (
        type(document.get("schema_version")) is not int
        or document.get("schema_version") != 1
        or type(document.get("events")) is not list
        or not document["events"]
        or type(document["events"][-1]) is not dict
    ):
        raise WebImpactHotPathError("web_impact_timeline_invalid")
    event = document["events"][-1]
    if (
        event.get("session") != step.role
        or event.get("source") != step.channel
        or event.get("method") != step.method
        or type(event.get("status")) is not int
        or type(event.get("cookie_transition")) is not dict
        or type(event.get("security_headers")) is not list
    ):
        raise WebImpactHotPathError(
            "web_impact_timeline_event_binding_mismatch"
        )
    return event


def _helper_metadata(
    payload: bytes,
    *,
    channel: str,
) -> tuple[int, bool]:
    document = _strict_json_file(
        payload,
        maximum_bytes=WEB_IMPACT_HOTPATH_MAX_METADATA_BYTES,
        code="web_impact_helper_metadata_invalid",
    )
    response = document.get("response")
    if (
        document.get("ok") is not True
        or type(response) is not dict
        or type(response.get("status")) is not int
    ):
        raise WebImpactHotPathError(
            "web_impact_helper_metadata_invalid"
        )
    truncated = (
        response.get("truncated")
        if channel == "http"
        else response.get("html_truncated")
    )
    if type(truncated) is not bool:
        raise WebImpactHotPathError(
            "web_impact_helper_truncation_unknown"
        )
    return response["status"], truncated


def _copy_snapshot_to_workspace(
    state_root: Path,
    snapshot: _Snapshot,
    destination: Path,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        copy_bounded_regular(
            state_root,
            snapshot.path,
            destination,
            maximum_bytes=WEB_IMPACT_MAX_ARTIFACT_BYTES,
            expected_sha256=snapshot.sha256,
            expected_size=snapshot.size_bytes,
            mode=0o400,
        )
    except (OSError, SafeFileError, ValueError) as error:
        raise WebImpactHotPathError(
            "web_impact_replay_input_copy_failed"
        ) from error


def _helper_argv(
    *,
    step: object,
    url: str,
    body_path: str | None,
) -> tuple[str, ...]:
    if step.channel == "http":
        values = [
            "/opt/ctf-templates/web/request.py",
            url,
            "-X",
            step.method,
            "--session",
            step.role,
            "--timeout",
            str(step.timeout_seconds),
            "--max-bytes",
            str(WEB_IMPACT_HOTPATH_HELPER_MAX_RESPONSE_BYTES),
        ]
        if body_path is not None:
            values.extend(("--data-file", body_path))
        if step.follow:
            values.append("--follow")
        if step.insecure:
            values.append("--insecure")
        return tuple(values)
    values = [
        "ctf-browser",
        url,
        "--session",
        step.role,
        "--timeout",
        str(step.timeout_seconds),
        "--max-html-bytes",
        str(WEB_IMPACT_HOTPATH_HELPER_MAX_RESPONSE_BYTES),
    ]
    if step.insecure:
        values.append("--insecure")
    return tuple(values)


def _artifact_bytes(
    engine: ChallengeEngine,
    state: ChallengeState,
    client: object,
    *,
    locator: str,
    destination: Path,
    maximum_bytes: int,
    workspace_root: Path,
) -> bytes:
    try:
        immutable = engine._snapshot_workspace_file(
            state,
            client,
            locator,
            destination,
            workspace_root=workspace_root,
        )
        return read_bounded_regular(
            engine.store.challenge_paths(state.identity).root,
            immutable.path.relative_to(
                engine.store.challenge_paths(state.identity).root
            ).as_posix(),
            maximum_bytes=maximum_bytes,
            expected_sha256=immutable.sha256,
            expected_size=immutable.size_bytes,
        )
    except (OSError, SafeFileError, ValueError) as error:
        raise WebImpactHotPathError(
            "web_impact_capture_snapshot_failed"
        ) from error


def _preissue_key(state: ChallengeState) -> dict[str, object]:
    value = state.extra.get("web_impact_preissues")
    if value is None:
        return {}
    if type(value) is not dict:
        raise WebImpactHotPathError(
            "web_impact_preissue_state_invalid"
        )
    if len(value) >= WEB_IMPACT_HOTPATH_MAX_ATTEMPTS:
        raise WebImpactHotPathError(
            "web_impact_preissue_history_full"
        )
    return value


def _preissue_document(
    *,
    attempt_id: str,
    state: ChallengeState,
    execution_plan: WebImpactExecutionPlan,
    driver: WebImpactDriverManifest,
    spec_snapshot: _Snapshot,
    driver_snapshot: _Snapshot,
    input_snapshots: tuple[_Snapshot, ...],
    replay_ids: tuple[_ReplayIds, ...],
    request_documents: tuple[dict[str, object], ...],
    request_payloads: tuple[bytes, ...],
    request_paths: tuple[str, ...],
    state_ids: WebImpactStateIds,
    target_bindings: tuple[tuple[str, WebImpactApprovedTarget], ...],
) -> dict[str, object]:
    return {
        "attempt_id": attempt_id,
        "authorities": {
            "automatic_submission_authorized": False,
            "candidate_authorized": False,
            "challenge_proof_satisfied": False,
            "executed_fact_authorized": False,
            "flag_proven": False,
            "progress_authorized": False,
            "status_transition_authorized": False,
        },
        "base_revision": state.revision,
        "configuration_epoch": state.configuration_epoch,
        "canonical_requests": [
            {
                "document": copy.deepcopy(document),
                "path": path,
                "sha256": _sha256(payload),
                "size_bytes": len(payload),
            }
            for document, payload, path in zip(
                request_documents,
                request_payloads,
                request_paths,
                strict=True,
            )
        ],
        "driver": driver_snapshot.to_dict(),
        "driver_sha256": driver.sha256,
        "execution_plan": execution_plan.to_dict(),
        "execution_plan_sha256": (
            execution_plan.execution_plan_sha256
        ),
        "expected_state_ids": {
            "evaluation_artifact_id": (
                state_ids.evaluation_artifact_id
            ),
            "experiment_id": state_ids.experiment_id,
            "fact_id": state_ids.fact_id,
            "operator_spec_artifact_id": (
                state_ids.operator_spec_artifact_id
            ),
            "plan_artifact_id": state_ids.plan_artifact_id,
            "progress_id": state_ids.progress_id,
        },
        "input_snapshots": [
            item.to_dict() for item in input_snapshots
        ],
        "operator_spec": spec_snapshot.to_dict(),
        "protocol": WEB_IMPACT_HOTPATH_PROTOCOL,
        "replays": [item.to_dict() for item in replay_ids],
        "runtime_image_digest": (
            execution_plan.specification.plan.runtime_image_digest
        ),
        "schema_version": WEB_IMPACT_HOTPATH_SCHEMA_VERSION,
        "source_manifest_sha256": (
            execution_plan.specification.plan.source_manifest_sha256
        ),
        "status": "issued",
        "targets": [
            {
                "approved": approved.to_dict(),
                "target_id": target_id,
            }
            for target_id, approved in target_bindings
        ],
        "terminal": None,
    }


def _ensure_driver_inputs_unique(
    driver: WebImpactDriverManifest,
) -> tuple[WebImpactDriverInput, ...]:
    values: list[WebImpactDriverInput] = []
    by_locator: dict[str, WebImpactDriverInput] = {}
    for step in driver.steps:
        for item in (step.route, step.body):
            if item is None:
                continue
            previous = by_locator.get(item.locator)
            if previous is not None and previous != item:
                raise WebImpactHotPathError(
                    "web_impact_driver_locator_rebound"
                )
            if previous is None:
                by_locator[item.locator] = item
                values.append(item)
    return tuple(values)


def _snapshot_by_locator(
    snapshots: tuple[_Snapshot, ...],
) -> dict[str, _Snapshot]:
    return {item.source_locator: item for item in snapshots}


def _verify_external_bindings(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    execution_plan: WebImpactExecutionPlan,
    driver: WebImpactDriverManifest,
    spec_snapshot: _Snapshot,
    driver_snapshot: _Snapshot,
    input_snapshots: tuple[_Snapshot, ...],
    request_documents: tuple[dict[str, object], ...],
    request_payloads: tuple[bytes, ...],
    request_paths: tuple[str, ...],
    target_ids: tuple[str, ...],
    configuration_epoch: int,
) -> None:
    current = engine.store.load(identity, recover=False)
    paths = engine.store.challenge_paths(identity)
    if (
        current.category != "web"
        or current.schema_version < STATE_SCHEMA_VERSION
        or current.configuration_epoch
        != configuration_epoch
        or engine.config.runtime.image_digest
        != execution_plan.specification.plan.runtime_image_digest
    ):
        raise WebImpactHotPathError(
            "web_impact_current_binding_changed"
        )
    inventory = inventory_challenge(engine.challenge_input(identity))
    if (
        inventory.manifest_sha256
        != execution_plan.specification.plan.source_manifest_sha256
        or current.metadata.get("source_manifest_sha256")
        != inventory.manifest_sha256
    ):
        raise WebImpactHotPathError(
            "web_impact_source_manifest_changed"
        )
    spec_payload = _read_snapshot(
        paths.root,
        spec_snapshot,
        maximum_bytes=WEB_IMPACT_OPERATOR_SPEC_MAX_BYTES,
    )
    driver_payload = _read_snapshot(
        paths.root,
        driver_snapshot,
        maximum_bytes=WEB_IMPACT_DRIVER_MAX_BYTES,
    )
    current_targets = tuple(
        _target_for_id(engine, current, target_id)
        for target_id in target_ids
    )
    vulnerable = _approved_target(current_targets[0])
    control = (
        _approved_target(current_targets[1])
        if len(current_targets) == 2
        else None
    )
    try:
        reparsed_spec = parse_web_impact_operator_spec(
            spec_payload,
            current_source_manifest_sha256=inventory.manifest_sha256,
            current_runtime_image_digest=engine.config.runtime.image_digest,
            current_vulnerable_target=vulnerable,
            current_control_target=control,
        )
        reparsed_driver = parse_web_impact_driver_manifest(
            driver_payload,
            operator_spec_payload=spec_payload,
        )
    except (ValueError, WebImpactExecutionPreflightError) as error:
        raise WebImpactHotPathError(
            "web_impact_spec_or_driver_revalidation_failed"
        ) from error
    if (
        reparsed_spec != execution_plan.specification
        or reparsed_driver != driver
    ):
        raise WebImpactHotPathError(
            "web_impact_spec_or_driver_rebound"
        )
    for snapshot in input_snapshots:
        _read_snapshot(
            paths.root,
            snapshot,
            maximum_bytes=WEB_IMPACT_MAX_ARTIFACT_BYTES,
        )
    for request, path, expected, expected_payload in zip(
        execution_plan.requests,
        request_paths,
        request_documents,
        request_payloads,
        strict=True,
    ):
        try:
            payload = read_bounded_regular(
                paths.root,
                path,
                maximum_bytes=256 * 1024,
                expected_sha256=_sha256(expected_payload),
                expected_size=len(expected_payload),
            )
            envelope = strict_json_loads(
                payload,
                max_bytes=256 * 1024,
                max_depth=16,
            )
        except (OSError, SafeFileError, StrictJSONError, ValueError) as error:
            raise WebImpactHotPathError(
                "web_impact_preissued_request_unavailable"
            ) from error
        if (
            payload != expected_payload
            or type(envelope) is not dict
            or envelope != expected
        ):
            raise WebImpactHotPathError(
                "web_impact_preissued_request_rebound"
            )


def _terminalize(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    attempt_id: str,
    error: BaseException,
) -> None:
    def apply(state: ChallengeState) -> None:
        attempts = state.extra.get("web_impact_preissues")
        if type(attempts) is not dict:
            return
        attempt = attempts.get(attempt_id)
        if type(attempt) is not dict:
            return
        if attempt.get("status") in {"completed", "interrupted"}:
            return
        attempt["status"] = "interrupted"
        attempt["terminal"] = {
            "at": utc_now(),
            "error_type": type(error).__name__[:128],
            "reason_code": "web_impact_execution_interrupted",
        }

    try:
        engine.store.update(identity, apply)
    except BaseException as terminal_error:
        error.add_note(
            "Web impact interruption terminalization failed: "
            f"{type(terminal_error).__name__}"
        )


def prove_web_impact(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    operator_spec_locator: str,
    driver_locator: str,
    hypothesis_ids: tuple[str, ...] = (),
    timeout_seconds: int = 900,
    _session_owned: bool = False,
) -> tuple[ChallengeState, WebImpactExecutionEvaluation]:
    """Execute one explicit Web impact proof without candidate authority."""

    # Import lazily to avoid a module cycle at ChallengeEngine definition time.
    from ctf_os.engine.challenge import (
        EngineError,
        SessionAlreadyRunning,
    )
    from ctf_os.store import ChallengeLock, LockTimeout

    if not _session_owned:
        lock = ChallengeLock(
            engine.store.challenge_paths(identity).runtime
            / "session.lock",
            timeout=0,
        )
        try:
            lock.acquire()
        except LockTimeout as error:
            raise SessionAlreadyRunning(
                f"another session already owns {identity.key}"
            ) from error
        try:
            engine._recover_session_boundary(identity)
            return prove_web_impact(
                engine,
                identity,
                operator_spec_locator=operator_spec_locator,
                driver_locator=driver_locator,
                hypothesis_ids=hypothesis_ids,
                timeout_seconds=timeout_seconds,
                _session_owned=True,
            )
        finally:
            lock.release()

    state = engine.store.load(identity)
    if (
        state.category != "web"
        or state.schema_version < STATE_SCHEMA_VERSION
    ):
        raise EngineError(
            "Web impact proof requires one schema-v2 Web challenge"
        )
    if (
        type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= 24 * 60 * 60
    ):
        raise EngineError("Web impact timeout must be 1..86400 seconds")
    manifest = inventory_challenge(engine.challenge_input(identity))
    if (
        state.metadata.get("source_manifest_sha256")
        != manifest.manifest_sha256
    ):
        raise EngineError(
            "Web impact proof requires a current immutable source manifest"
        )
    if engine.config.runtime.image_digest is None:
        raise EngineError(
            "Web impact proof requires a digest-pinned runtime image"
        )

    paths = engine.store.challenge_paths(identity)
    attempt_id = _new_id("web-impact")
    attempt_root = ensure_private_directory(
        paths.artifacts / "web-impact"
    )
    input_root = ensure_private_directory(
        attempt_root / "inputs" / attempt_id
    )
    initial_client = engine.sandbox(
        state,
        network_policy_override=NetworkPolicy.deny_all(),
    )
    spec_artifact_id = _new_id("A-web-spec")
    driver_artifact_id = _new_id("A-web-driver")
    spec_snapshot = _snapshot_workspace_input(
        engine,
        state,
        client=initial_client,
        artifact_id=spec_artifact_id,
        locator=operator_spec_locator,
        destination=attempt_root / f"{spec_artifact_id}.json",
        role="operator_spec",
    )
    spec_payload = _read_snapshot(
        paths.root,
        spec_snapshot,
        maximum_bytes=WEB_IMPACT_OPERATOR_SPEC_MAX_BYTES,
    )
    driver_snapshot = _snapshot_workspace_input(
        engine,
        state,
        client=initial_client,
        artifact_id=driver_artifact_id,
        locator=driver_locator,
        destination=input_root / f"{driver_artifact_id}.json",
        role="driver",
    )
    driver_payload = _read_snapshot(
        paths.root,
        driver_snapshot,
        maximum_bytes=WEB_IMPACT_DRIVER_MAX_BYTES,
    )
    try:
        driver = parse_web_impact_driver_manifest(
            driver_payload,
            operator_spec_payload=spec_payload,
        )
    except ValueError as error:
        raise EngineError(f"Web impact driver rejected: {error}") from error

    vulnerable_record = _target_for_id(
        engine,
        state,
        driver.vulnerable_target_id,
    )
    control_record = (
        _target_for_id(engine, state, driver.control_target_id)
        if driver.control_target_id is not None
        else None
    )
    vulnerable_target = _approved_target(vulnerable_record)
    control_target = (
        _approved_target(control_record)
        if control_record is not None
        else None
    )
    try:
        specification = parse_web_impact_operator_spec(
            spec_payload,
            current_source_manifest_sha256=manifest.manifest_sha256,
            current_runtime_image_digest=engine.config.runtime.image_digest,
            current_vulnerable_target=vulnerable_target,
            current_control_target=control_target,
        )
        driver.validate_timeline(specification.plan.timeline)
    except ValueError as error:
        raise EngineError(
            f"Web impact operator specification rejected: {error}"
        ) from error
    expected_trace_contract = web_impact_trace_contract_sha256(
        source_kind=specification.plan.source_sink.source_kind,
        source_pointer_sha256=(
            specification.plan.source_sink.source_pointer_sha256
        ),
        sink_kind=specification.plan.source_sink.sink_kind,
        sink_pointer_sha256=(
            specification.plan.source_sink.sink_pointer_sha256
        ),
        runtime_step_ordinal=(
            specification.plan.source_sink.runtime_step_ordinal
        ),
    )
    if (
        specification.plan.source_sink.trace_contract_sha256
        != expected_trace_contract
    ):
        raise EngineError(
            "Web impact source/sink trace contract is not engine-derived"
        )
    if (control_record is None) != (
        specification.control_target is None
    ):
        raise EngineError(
            "Web impact control target and differential must match"
        )

    input_snapshots: list[_Snapshot] = []
    for position, item in enumerate(
        _ensure_driver_inputs_unique(driver),
        start=1,
    ):
        input_snapshots.append(
            _snapshot_workspace_input(
                engine,
                state,
                client=initial_client,
                artifact_id=_new_id("A-web-input"),
                locator=item.locator,
                destination=input_root
                / f"input-{position:04d}.bin",
                role="driver_input",
                expected_sha256=item.sha256,
                expected_size=item.size_bytes,
            )
        )
    selected_input_snapshots = tuple(input_snapshots)

    issue_count = 3 * (2 if control_record is not None else 1)
    replay_ids: list[_ReplayIds] = []
    issues: list[WebImpactReplayIssue] = []
    for _position in range(issue_count):
        request_id = _new_id("WREQ")
        run_id = _new_id("WRUN")
        issues.append(
            WebImpactReplayIssue(
                request_id=request_id,
                run_id=run_id,
                replay_nonce=secrets.token_bytes(32),
            )
        )
        replay_ids.append(
            _ReplayIds(
                request_id=request_id,
                run_id=run_id,
                receipt_id=_new_id("WREC"),
                request_artifact_ids=tuple(
                    _new_id("A-web-request")
                    for _step in driver.steps
                ),
                response_artifact_ids=tuple(
                    _new_id("A-web-response")
                    for _step in driver.steps
                ),
                trace_artifact_id=_new_id("A-web-trace"),
            )
        )
    try:
        execution_plan = plan_web_impact_execution(
            specification,
            tuple(issues),
        )
    except ValueError as error:
        raise EngineError(
            f"Web impact execution plan rejected: {error}"
        ) from error
    selected_replay_ids = tuple(replay_ids)
    for expected, actual in zip(
        execution_plan.requests,
        selected_replay_ids,
        strict=True,
    ):
        if (
            expected.request_id != actual.request_id
            or expected.run_id != actual.run_id
        ):
            raise EngineError("Web impact replay identity derivation failed")

    state_ids = WebImpactStateIds(
        experiment_id=_new_id("E-web-impact"),
        operator_spec_artifact_id=spec_artifact_id,
        plan_artifact_id=_new_id("A-web-plan"),
        evaluation_artifact_id=_new_id("A-web-evaluation"),
        fact_id=_new_id("F-web-impact"),
        progress_id=_new_id("P-web-impact"),
    )
    reserved = _all_state_ids(state)
    issued_ids = {
        state_ids.experiment_id,
        state_ids.operator_spec_artifact_id,
        state_ids.plan_artifact_id,
        state_ids.evaluation_artifact_id,
        state_ids.fact_id,
        state_ids.progress_id,
        driver_artifact_id,
        *(item.artifact_id for item in selected_input_snapshots),
        *(
            value
            for item in selected_replay_ids
            for value in (
                item.request_id,
                item.run_id,
                item.receipt_id,
                *item.request_artifact_ids,
                *item.response_artifact_ids,
                item.trace_artifact_id,
            )
        ),
    }
    if (
        None in issued_ids
        or len(issued_ids) != (
            6
            + 1
            + len(selected_input_snapshots)
            + sum(
                3
                + len(item.request_artifact_ids)
                + len(item.response_artifact_ids)
                + 1
                for item in selected_replay_ids
            )
        )
        or reserved & issued_ids
    ):
        raise EngineError(
            "Web impact preissued identifiers collide globally"
        )

    request_documents: list[dict[str, object]] = []
    request_payloads: list[bytes] = []
    request_paths: list[str] = []
    for request in execution_plan.requests:
        run_paths = engine.store.create_run(
            identity,
            request.run_id,
            request={
                "protocol": WEB_IMPACT_HOTPATH_PROTOCOL,
                "web_impact_request": request.to_dict(),
                "web_impact_request_sha256": request.request_sha256,
            },
            base_revision=state.revision,
        )
        request_payload = run_paths.request.read_bytes()
        payload = strict_json_loads(
            request_payload,
            max_bytes=256 * 1024,
            max_depth=16,
        )
        if type(payload) is not dict:
            raise EngineError(
                "Web impact request envelope is not canonical"
            )
        request_documents.append(payload)
        request_payloads.append(request_payload)
        request_paths.append(
            run_paths.request.relative_to(paths.root).as_posix()
        )
    selected_request_documents = tuple(request_documents)
    selected_request_payloads = tuple(request_payloads)
    selected_request_paths = tuple(request_paths)
    target_bindings = (
        (driver.vulnerable_target_id, vulnerable_target),
        *(
            (
                (driver.control_target_id, control_target),
            )
            if driver.control_target_id is not None
            and control_target is not None
            else ()
        ),
    )
    preissue = _preissue_document(
        attempt_id=attempt_id,
        state=state,
        execution_plan=execution_plan,
        driver=driver,
        spec_snapshot=spec_snapshot,
        driver_snapshot=driver_snapshot,
        input_snapshots=selected_input_snapshots,
        replay_ids=selected_replay_ids,
        request_documents=selected_request_documents,
        request_payloads=selected_request_payloads,
        request_paths=selected_request_paths,
        state_ids=state_ids,
        target_bindings=target_bindings,
    )
    preissue_sha256 = _sha256(_canonical_json_bytes(preissue))
    target_ids = tuple(
        item
        for item in (
            driver.vulnerable_target_id,
            driver.control_target_id,
        )
        if item is not None
    )

    def verify_preissue() -> None:
        _verify_external_bindings(
            engine,
            identity,
            execution_plan=execution_plan,
            driver=driver,
            spec_snapshot=spec_snapshot,
            driver_snapshot=driver_snapshot,
            input_snapshots=selected_input_snapshots,
            request_documents=selected_request_documents,
            request_payloads=selected_request_payloads,
            request_paths=selected_request_paths,
            target_ids=target_ids,
            configuration_epoch=state.configuration_epoch,
        )

    def commit_preissue(current: ChallengeState) -> None:
        if (
            current.revision != state.revision
            or current.configuration_epoch != state.configuration_epoch
            or _all_state_ids(current) != reserved
        ):
            raise EngineError(
                "Web impact state changed before temporal preissue"
            )
        attempts = _preissue_key(current)
        if any(
            type(value) is dict
            and value.get("status") in {"issued", "running"}
            for value in attempts.values()
        ):
            raise EngineError(
                "another Web impact execution is already active"
            )
        attempts[attempt_id] = copy.deepcopy(preissue)
        current.extra["web_impact_preissues"] = attempts

    committed_preissue = engine.store.update(
        identity,
        commit_preissue,
        expected_revision=state.revision,
        pre_replace_guard=verify_preissue,
    )
    try:
        committed_attempts = committed_preissue.extra.get(
            "web_impact_preissues"
        )
        if (
            type(committed_attempts) is not dict
            or committed_attempts.get(attempt_id) != preissue
            or _sha256(
                _canonical_json_bytes(committed_attempts[attempt_id])
            )
            != preissue_sha256
        ):
            raise EngineError(
                "Web impact temporal preissue was not durably committed"
            )

        def mark_running(current: ChallengeState) -> None:
            attempts = current.extra.get("web_impact_preissues")
            if type(attempts) is not dict:
                raise EngineError("Web impact preissue disappeared")
            attempt = attempts.get(attempt_id)
            if (
                type(attempt) is not dict
                or attempt.get("status") != "issued"
            ):
                raise EngineError(
                    "Web impact preissue is not executable"
                )
            attempt["status"] = "running"

        engine.store.update(
            identity,
            mark_running,
            expected_revision=committed_preissue.revision,
            pre_replace_guard=verify_preissue,
        )
    except BaseException as error:
        _terminalize(engine, identity, attempt_id, error)
        raise

    transports: list[WebImpactReplayTransportObservation] = []
    replay_wall_seconds: dict[str, float] = {}
    created_capture_paths: list[Path] = []
    try:
        inputs_by_locator = _snapshot_by_locator(
            selected_input_snapshots
        )
        capture_root = ensure_private_directory(
            attempt_root / "captures"
        )
        for request, ids in zip(
            execution_plan.requests,
            selected_replay_ids,
            strict=True,
        ):
            verify_preissue()
            latest = engine.store.load(identity, recover=False)
            if latest.configuration_epoch != state.configuration_epoch:
                raise WebImpactHotPathError(
                    "web_impact_configuration_epoch_changed"
                )
            target_record = (
                control_record
                if request.replay_target_kind == "control"
                else vulnerable_record
            )
            assert target_record is not None
            target = NetworkTarget.parse(target_record.endpoint)
            policy = engine._network_policy_for_target(target_record)
            work = ensure_private_directory(
                paths.runtime
                / "web-impact-live"
                / attempt_id
                / ids.run_id
                / "work"
            )
            if any(work.iterdir()):
                raise WebImpactHotPathError(
                    "web_impact_replay_workspace_not_fresh"
                )
            scope = ChallengeScope(
                contest_id=identity.contest_id,
                category=identity.category,
                challenge_id=identity.challenge_id,
                challenge_dir=engine.challenge_input(identity),
                work_dir=work,
            )
            epoch_path = reset_private_web_identity_state(
                scope,
                request.identity_epoch_sha256,
            )
            if (
                private_web_identity_epoch_sha256(scope)
                != request.identity_epoch_sha256
                or not epoch_path.is_file()
            ):
                raise WebImpactHotPathError(
                    "web_impact_identity_epoch_not_fresh"
                )
            client = engine.sandbox(
                latest,
                workspace_override=work,
                network_policy_override=policy,
            )
            client.initialize_workspace()
            event_values: list[WebTimelineEvent] = []
            captured_values: list[WebImpactCapturedArtifact] = []
            started = time.monotonic()
            replay_truncated = False
            replay_timed_out = False
            for step, request_artifact_id, response_artifact_id in zip(
                driver.steps,
                ids.request_artifact_ids,
                ids.response_artifact_ids,
                strict=True,
            ):
                route_snapshot = inputs_by_locator[step.route.locator]
                route_payload = _read_snapshot(
                    paths.root,
                    route_snapshot,
                    maximum_bytes=WEB_IMPACT_MAX_ARTIFACT_BYTES,
                )
                route = validate_route_payload(route_payload)
                body_path: str | None = None
                if step.body is not None:
                    body_snapshot = inputs_by_locator[step.body.locator]
                    body_destination = (
                        work
                        / "web-impact-inputs"
                        / f"body-step-{step.ordinal}.bin"
                    )
                    _copy_snapshot_to_workspace(
                        paths.root,
                        body_snapshot,
                        body_destination,
                    )
                    body_path = (
                        "/work/web-impact-inputs/"
                        f"body-step-{step.ordinal}.bin"
                    )
                request_capture = _request_capture_payload(
                    request=request,
                    step=step,
                    target=request.target,
                )
                request_capture_path = (
                    work
                    / "web-impact-inputs"
                    / f"request-step-{step.ordinal}.json"
                )
                request_capture_path.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                    mode=0o700,
                )
                atomic_write_bytes(
                    request_capture_path,
                    request_capture,
                    mode=0o400,
                )
                request_destination = (
                    capture_root / f"{request_artifact_id}.bin"
                )
                created_capture_paths.append(request_destination)
                persisted_request = _artifact_bytes(
                    engine,
                    latest,
                    client,
                    locator=request_capture_path.relative_to(
                        work
                    ).as_posix(),
                    destination=request_destination,
                    maximum_bytes=WEB_IMPACT_MAX_ARTIFACT_BYTES,
                    workspace_root=work,
                )
                url = _target_origin(target_record) + route
                engine._wait_for_remote_command_start(latest, target)
                result = client.run(
                    CommandSpec(
                        argv=_helper_argv(
                            step=step,
                            url=url,
                            body_path=body_path,
                        ),
                        timeout_seconds=step.timeout_seconds,
                        summary_bytes=0,
                        network_target=target,
                        resource_request=ResourceVector(
                            cpu=1,
                            memory_mib=2 * 1024,
                            network=1,
                        ),
                    )
                )
                replay_timed_out = replay_timed_out or (
                    result.timed_out is True
                )
                if (
                    result.status != "completed"
                    or type(result.exit_code) is not int
                    or result.exit_code != 0
                    or result.timed_out is not False
                    or result.orchestration_error is not None
                ):
                    raise WebImpactHotPathError(
                        f"web_impact_helper_step_{step.ordinal}_failed"
                    )
                metadata_locator = (
                    "web/response.json"
                    if step.channel == "http"
                    else "web/browser.json"
                )
                response_locator = (
                    "web/body.bin"
                    if step.channel == "http"
                    else "web/browser.html"
                )
                metadata_ref = client.register_artifact(
                    metadata_locator,
                    maximum_bytes=WEB_IMPACT_HOTPATH_MAX_METADATA_BYTES,
                )
                metadata_payload = read_bounded_regular(
                    work,
                    metadata_ref.locator,
                    maximum_bytes=(
                        WEB_IMPACT_HOTPATH_MAX_METADATA_BYTES
                    ),
                    expected_sha256=metadata_ref.sha256,
                    expected_size=metadata_ref.size_bytes,
                )
                if (
                    _sha256(metadata_payload) != metadata_ref.sha256
                    or len(metadata_payload)
                    != metadata_ref.size_bytes
                ):
                    raise WebImpactHotPathError(
                        "web_impact_helper_metadata_rebound"
                    )
                status, truncated = _helper_metadata(
                    metadata_payload,
                    channel=step.channel,
                )
                replay_truncated = replay_truncated or truncated
                timeline_ref = client.register_artifact(
                    "web/timeline.json",
                    maximum_bytes=WEB_IMPACT_HOTPATH_MAX_METADATA_BYTES,
                )
                timeline_payload = read_bounded_regular(
                    work,
                    timeline_ref.locator,
                    maximum_bytes=(
                        WEB_IMPACT_HOTPATH_MAX_METADATA_BYTES
                    ),
                    expected_sha256=timeline_ref.sha256,
                    expected_size=timeline_ref.size_bytes,
                )
                if (
                    _sha256(timeline_payload) != timeline_ref.sha256
                    or len(timeline_payload)
                    != timeline_ref.size_bytes
                ):
                    raise WebImpactHotPathError(
                        "web_impact_timeline_rebound"
                    )
                timeline_event = _latest_timeline_event(
                    timeline_payload,
                    step=step,
                )
                response_destination = (
                    capture_root / f"{response_artifact_id}.bin"
                )
                created_capture_paths.append(response_destination)
                response_payload = _artifact_bytes(
                    engine,
                    latest,
                    client,
                    locator=response_locator,
                    destination=response_destination,
                    maximum_bytes=WEB_IMPACT_MAX_ARTIFACT_BYTES,
                    workspace_root=work,
                )
                request_commitment = WebArtifactCommitment(
                    artifact_id=request_artifact_id,
                    sha256=_sha256(persisted_request),
                    size_bytes=len(persisted_request),
                )
                response_commitment = WebArtifactCommitment(
                    artifact_id=response_artifact_id,
                    sha256=_sha256(response_payload),
                    size_bytes=len(response_payload),
                )
                event_values.append(
                    WebTimelineEvent(
                        ordinal=step.ordinal,
                        channel=step.channel,
                        role=step.role,
                        method=step.method,
                        route_binding_sha256=(
                            step.route_binding_sha256
                        ),
                        request_shape_sha256=(
                            step.request_shape_sha256
                        ),
                        status=status,
                        request_artifact=request_commitment,
                        response_artifact=response_commitment,
                        cookie_transition_sha256=_sha256(
                            _canonical_json_bytes(
                                timeline_event["cookie_transition"]
                            )
                        ),
                        security_context_sha256=_sha256(
                            _canonical_json_bytes(
                                {
                                    "identity_epoch_sha256": (
                                        request.identity_epoch_sha256
                                    ),
                                    "principal_binding_sha256": next(
                                        item.principal_binding_sha256
                                        for item in specification.plan.identities
                                        if item.role == step.role
                                    ),
                                    "role": step.role,
                                    "security_headers": (
                                        timeline_event[
                                            "security_headers"
                                        ]
                                    ),
                                }
                            )
                        ),
                    )
                )
                captured_values.extend(
                    (
                        WebImpactCapturedArtifact(
                            artifact_id=request_artifact_id,
                            payload=persisted_request,
                        ),
                        WebImpactCapturedArtifact(
                            artifact_id=response_artifact_id,
                            payload=response_payload,
                        ),
                    )
                )
            sink_event = event_values[
                specification.plan.oracle.sink_step_ordinal - 1
            ]
            # Sink reachability is a transport/data-flow observation, not the
            # impact oracle itself.  The designated vulnerable runtime step
            # completed and its response was captured above; exact expected
            # response bytes are checked separately by ``_oracle_valid``.
            # Controls represent the declared non-vulnerable branch.
            reached_sink = (
                request.replay_target_kind == "vulnerable"
                and sink_event.status
                == specification.plan.oracle.expected_status
            )
            trace_payload = _canonical_json_bytes(
                {
                    "events": [
                        {
                            "cookie_transition_sha256": (
                                item.cookie_transition_sha256
                            ),
                            "ordinal": item.ordinal,
                            "request_sha256": (
                                item.request_artifact.sha256
                            ),
                            "response_sha256": (
                                item.response_artifact.sha256
                            ),
                            "security_context_sha256": (
                                item.security_context_sha256
                            ),
                            "status": item.status,
                        }
                        for item in event_values
                    ],
                    "identity_epoch_sha256": (
                        request.identity_epoch_sha256
                    ),
                    "protocol": WEB_IMPACT_HOTPATH_PROTOCOL,
                    "reached_sink": reached_sink,
                    "runtime_step_ordinal": (
                        specification.plan.source_sink
                        .runtime_step_ordinal
                    ),
                    "sink_pointer_sha256": (
                        specification.plan.source_sink
                        .sink_pointer_sha256
                    ),
                    "source_pointer_sha256": (
                        specification.plan.source_sink
                        .source_pointer_sha256
                    ),
                    "trace_contract_sha256": (
                        specification.plan.source_sink
                        .trace_contract_sha256
                    ),
                }
            )
            if len(trace_payload) > WEB_IMPACT_MAX_TRACE_BYTES:
                raise WebImpactHotPathError(
                    "web_impact_runtime_trace_too_large"
                )
            trace_destination = (
                capture_root / f"{ids.trace_artifact_id}.bin"
            )
            created_capture_paths.append(trace_destination)
            atomic_write_bytes(
                trace_destination,
                trace_payload,
                mode=0o400,
            )
            trace_commitment = WebArtifactCommitment(
                artifact_id=ids.trace_artifact_id,
                sha256=_sha256(trace_payload),
                size_bytes=len(trace_payload),
            )
            captured_values.append(
                WebImpactCapturedArtifact(
                    artifact_id=ids.trace_artifact_id,
                    payload=trace_payload,
                )
            )
            observation = WebImpactReplayObservation(
                target_kind=request.replay_target_kind,
                replay_ordinal=request.replay_ordinal,
                run_id=request.run_id,
                receipt_id=ids.receipt_id,
                receipt_sha256="0" * 64,
                replay_nonce_sha256=request.replay_nonce_sha256,
                identity_epoch_sha256=(
                    request.identity_epoch_sha256
                ),
                execution_contract_sha256=(
                    request.semantic_execution_contract_sha256
                ),
                plan_sha256=request.plan_sha256,
                source_manifest_sha256=(
                    request.source_manifest_sha256
                ),
                runtime_image_digest=request.runtime_image_digest,
                authorized_target_binding_sha256=(
                    request.target.binding_sha256
                ),
                target_generation=request.target.generation,
                clean_workspace=True,
                fresh_identity_state=(
                    private_web_identity_epoch_sha256(scope)
                    == request.identity_epoch_sha256
                ),
                network_target_authorized=True,
                orchestration_status="completed",
                exit_code=0,
                timed_out=replay_timed_out,
                capture_complete=True,
                truncation_known=True,
                truncated=replay_truncated,
                capture_error=None,
                timeline=tuple(event_values),
                source_sink=WebSourceSinkObservation(
                    source_kind=(
                        specification.plan.source_sink.source_kind
                    ),
                    source_pointer_sha256=(
                        specification.plan.source_sink
                        .source_pointer_sha256
                    ),
                    sink_kind=(
                        specification.plan.source_sink.sink_kind
                    ),
                    sink_pointer_sha256=(
                        specification.plan.source_sink
                        .sink_pointer_sha256
                    ),
                    runtime_step_ordinal=(
                        specification.plan.source_sink
                        .runtime_step_ordinal
                    ),
                    runtime_request_sha256=(
                        event_values[
                            specification.plan.source_sink
                            .runtime_step_ordinal
                            - 1
                        ].request_artifact.sha256
                    ),
                    trace_contract_sha256=(
                        specification.plan.source_sink
                        .trace_contract_sha256
                    ),
                    trace_artifact=trace_commitment,
                    reached_sink=reached_sink,
                ),
            )
            receipt = build_web_impact_execution_receipt(
                request,
                observation,
                tuple(captured_values),
                orchestration_status="completed",
                exit_code=0,
                timed_out=replay_timed_out,
                clean_workspace=True,
                fresh_identity_state=(
                    observation.fresh_identity_state
                ),
                network_target_authorized=True,
                capture_complete=True,
                truncation_known=True,
                truncated=replay_truncated,
                capture_error_code=None,
            )
            observation = replace(
                observation,
                receipt_sha256=receipt.sha256,
            )
            receipt_path = (
                engine.store.run_paths(identity, request.run_id).root
                / "web-impact-receipt.json"
            )
            atomic_write_bytes(
                receipt_path,
                receipt.canonical_bytes,
                mode=0o400,
            )
            engine.store.write_run_result(
                identity,
                request.run_id,
                {
                    "capture_artifact_ids": [
                        item.artifact_id for item in captured_values
                    ],
                    "observation_commitment_sha256": (
                        receipt.observation_commitment_sha256
                    ),
                    "protocol": WEB_IMPACT_HOTPATH_PROTOCOL,
                    "receipt_id": ids.receipt_id,
                    "receipt_sha256": receipt.sha256,
                },
            )
            engine.store.write_run_validation(
                identity,
                request.run_id,
                {
                    "ok": (
                        replay_timed_out is False
                        and replay_truncated is False
                    ),
                    "protocol": WEB_IMPACT_HOTPATH_PROTOCOL,
                    "request_sha256": request.request_sha256,
                    "transport_execution_contract_sha256": (
                        request.transport_execution_contract_sha256
                    ),
                },
            )
            transports.append(
                WebImpactReplayTransportObservation(
                    request_payload=request.canonical_bytes,
                    receipt_payload=receipt.canonical_bytes,
                    semantic_observation=observation,
                    artifacts=tuple(captured_values),
                )
            )
            replay_wall_seconds[request.run_id] = (
                time.monotonic() - started
            )

        verify_preissue()
        evaluation = evaluate_web_impact_execution(
            execution_plan,
            tuple(transports),
            operator_spec_payload=spec_payload,
            current_source_manifest_sha256=manifest.manifest_sha256,
            current_runtime_image_digest=engine.config.runtime.image_digest,
            current_vulnerable_target=vulnerable_target,
            current_control_target=control_target,
        )
        plan_path = (
            attempt_root / f"{state_ids.plan_artifact_id}.json"
        )
        evaluation_path = (
            attempt_root
            / f"{state_ids.evaluation_artifact_id}.json"
        )
        atomic_write_bytes(
            plan_path,
            execution_plan.canonical_bytes,
            mode=0o400,
        )
        atomic_write_bytes(
            evaluation_path,
            evaluation.canonical_bytes,
            mode=0o400,
        )
        final_base = engine.store.load(identity, recover=False)
        projection_ids = state_ids
        if not evaluation.confirmed:
            projection_ids = WebImpactStateIds(
                experiment_id=state_ids.experiment_id,
                operator_spec_artifact_id=(
                    state_ids.operator_spec_artifact_id
                ),
                plan_artifact_id=state_ids.plan_artifact_id,
                evaluation_artifact_id=(
                    state_ids.evaluation_artifact_id
                ),
                fact_id=None,
                progress_id=None,
            )
        projection = build_web_impact_state_projection(
            evaluation,
            execution_plan,
            spec_payload,
            identity=identity,
            configuration_epoch=state.configuration_epoch,
            base_revision=state.revision,
            ids=projection_ids,
            hypothesis_ids=hypothesis_ids,
            evaluated_at=utc_now(),
            timeout_seconds=timeout_seconds,
            run_origin=RunOrigin.OPERATOR_TOOL,
            replay_wall_seconds={
                record.run_id: replay_wall_seconds[record.run_id]
                for record in evaluation.records
            },
            existing_global_ids=_projection_reserved_ids(final_base),
        )
        driver_and_inputs = (
            _snapshot_artifact_reference(driver_snapshot),
            *(
                _snapshot_artifact_reference(item)
                for item in selected_input_snapshots
            ),
        )

        def verify_final() -> None:
            verify_preissue()
            for transport, ids in zip(
                transports,
                selected_replay_ids,
                strict=True,
            ):
                for captured in transport.artifacts:
                    payload = read_bounded_regular(
                        paths.root,
                        (
                            capture_root
                            / f"{captured.artifact_id}.bin"
                        ).relative_to(paths.root).as_posix(),
                        maximum_bytes=WEB_IMPACT_MAX_ARTIFACT_BYTES,
                        expected_sha256=_sha256(captured.payload),
                        expected_size=len(captured.payload),
                    )
                    if payload != captured.payload:
                        raise WebImpactHotPathError(
                            "web_impact_capture_changed_before_commit"
                        )
                receipt_payload = read_bounded_regular(
                    paths.root,
                    (
                        engine.store.run_paths(
                            identity,
                            ids.run_id,
                        ).root
                        / "web-impact-receipt.json"
                    ).relative_to(paths.root).as_posix(),
                    maximum_bytes=256 * 1024,
                    expected_sha256=_sha256(
                        transport.receipt_payload
                    ),
                    expected_size=len(transport.receipt_payload),
                )
                if receipt_payload != transport.receipt_payload:
                    raise WebImpactHotPathError(
                        "web_impact_receipt_changed_before_commit"
                    )
            recomputed = evaluate_web_impact_execution(
                execution_plan,
                tuple(transports),
                operator_spec_payload=spec_payload,
                current_source_manifest_sha256=(
                    manifest.manifest_sha256
                ),
                current_runtime_image_digest=(
                    engine.config.runtime.image_digest
                ),
                current_vulnerable_target=vulnerable_target,
                current_control_target=control_target,
            )
            if recomputed != evaluation:
                raise WebImpactHotPathError(
                    "web_impact_evaluation_recomputed_differently"
                )
            if read_bounded_regular(
                paths.root,
                plan_path.relative_to(paths.root).as_posix(),
                maximum_bytes=2 * 1024 * 1024,
                expected_sha256=_sha256(
                    execution_plan.canonical_bytes
                ),
                expected_size=len(execution_plan.canonical_bytes),
            ) != execution_plan.canonical_bytes:
                raise WebImpactHotPathError(
                    "web_impact_plan_artifact_changed"
                )
            if read_bounded_regular(
                paths.root,
                evaluation_path.relative_to(paths.root).as_posix(),
                maximum_bytes=2 * 1024 * 1024,
                expected_sha256=_sha256(evaluation.canonical_bytes),
                expected_size=len(evaluation.canonical_bytes),
            ) != evaluation.canonical_bytes:
                raise WebImpactHotPathError(
                    "web_impact_evaluation_artifact_changed"
                )
            validate_web_impact_state_projection(
                projection,
                evaluation=evaluation,
                execution_plan=execution_plan,
                operator_spec_payload=spec_payload,
                existing_global_ids=_projection_reserved_ids(final_base),
            )

        def append_graph(current: ChallengeState) -> None:
            if (
                current.revision != final_base.revision
                or current.configuration_epoch
                != state.configuration_epoch
                or _all_state_ids(current)
                != _all_state_ids(final_base)
            ):
                raise EngineError(
                    "Web impact state changed before graph commit"
                )
            attempts = current.extra.get("web_impact_preissues")
            if type(attempts) is not dict:
                raise EngineError("Web impact preissue disappeared")
            attempt = attempts.get(attempt_id)
            if (
                type(attempt) is not dict
                or attempt.get("status") != "running"
                or attempt.get("terminal") is not None
            ):
                raise EngineError(
                    "Web impact preissue is no longer running"
                )
            validate_web_impact_state_projection(
                projection,
                evaluation=evaluation,
                execution_plan=execution_plan,
                operator_spec_payload=spec_payload,
                existing_global_ids=_projection_reserved_ids(current),
            )
            current.experiments.append(projection.experiment)
            current.runs.extend(projection.runs)
            current.receipts.extend(projection.receipts)
            current.artifacts.extend(projection.artifacts)
            current.artifacts.extend(driver_and_inputs)
            if projection.fact is not None:
                current.facts.append(projection.fact)
            if projection.progress is not None:
                current.progress_markers.append(projection.progress)
            attempt["status"] = "completed"
            attempt["terminal"] = {
                "at": utc_now(),
                "evaluation_sha256": evaluation.sha256,
                "projection_sha256": projection.sha256,
                "reason_code": (
                    "web_impact_confirmed"
                    if evaluation.confirmed
                    else "web_impact_rejected"
                ),
            }
            validate_web_impact_state_graph(current)

        committed = engine.store.update(
            identity,
            append_graph,
            expected_revision=final_base.revision,
            pre_replace_guard=verify_final,
        )
        validate_web_impact_state_graph(committed)
        return committed, evaluation
    except BaseException as error:
        _terminalize(engine, identity, attempt_id, error)
        raise


__all__ = [
    "WEB_IMPACT_HOTPATH_PROTOCOL",
    "WEB_IMPACT_HOTPATH_SCHEMA_VERSION",
    "WebImpactHotPathError",
    "prove_web_impact",
]
