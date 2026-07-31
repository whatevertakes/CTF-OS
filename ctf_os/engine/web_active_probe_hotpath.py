"""Temporally pre-issued Web race/OOB execution hot path.

One call owns one already-open Web challenge.  All six replay identities and
raw-free request commitments are durable before the first network request.
Each replay receives a fresh role cookie epoch, runs optional exact setup
requests, and then invokes the image-owned active probe.  The helper performs
either one bounded barrier race or one sandbox-local callback observation.
"""

from __future__ import annotations

import copy
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ctf_os.director.resources import ResourceVector
from ctf_os.engine.web_active_probe import (
    WEB_ACTIVE_PROBE_MAX_ARTIFACT_BYTES,
    WEB_ACTIVE_PROBE_MAX_DRIVER_BYTES,
    WEB_ACTIVE_PROBE_MAX_REPORT_BYTES,
    WEB_ACTIVE_PROBE_MAX_SPEC_BYTES,
    WEB_ACTIVE_PROBE_OPERATOR_PROTOCOL,
    WEB_ACTIVE_PROBE_REPETITIONS,
    WebActiveProbeDriver,
    classify_web_active_probe_report,
    evaluate_web_active_probe_records,
    parse_web_active_probe_driver,
    parse_web_active_probe_operator_spec,
)
from ctf_os.engine.web_impact_driver import (
    WebImpactDriverInput,
    validate_route_payload,
    web_impact_target_binding_sha256,
)
from ctf_os.engine.web_impact_hotpath import (
    _all_state_ids,
    _artifact_bytes,
    _copy_snapshot_to_workspace,
    _helper_argv,
    _helper_metadata,
    _new_id,
    _read_snapshot,
    _snapshot_workspace_input,
    _target_for_id,
    _target_origin,
)
from ctf_os.engine.web_active_probe_state import (
    validate_web_active_probe_state_graph,
)
from ctf_os.models import (
    ArtifactReference,
    ChallengeIdentity,
    ChallengeState,
    ExecutionReceipt,
    Experiment,
    ExperimentKind,
    ExperimentStatus,
    Fact,
    ProgressMarker,
    Provenance,
    ReceiptOutcome,
    RunOrigin,
    RunReference,
    RunStatus,
    TargetRecord,
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
    ensure_private_directory,
    read_bounded_regular,
)
from ctf_os.sandbox.web_private import (
    private_web_cookie_lineage_sha256,
    private_web_identity_epoch_sha256,
    reset_private_web_identity_state,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.stages.ingest import inventory_challenge
from ctf_os.store.atomic import (
    StrictJSONError,
    atomic_write_bytes,
    strict_json_loads,
)

if TYPE_CHECKING:
    from ctf_os.engine.challenge import ChallengeEngine


WEB_ACTIVE_PROBE_HOTPATH_PROTOCOL = (
    "ctfos.web.active_probe.hotpath.v1"
)
WEB_ACTIVE_PROBE_HOTPATH_SCHEMA_VERSION = 1
WEB_ACTIVE_PROBE_PREISSUES_KEY = "web_active_probe_preissues"
WEB_ACTIVE_PROBE_GRAPHS_KEY = "web_active_probe_graphs"
WEB_ACTIVE_PROBE_HELPER_PATH = (
    "/opt/ctf-templates/web/active_probe.py"
)
WEB_ACTIVE_PROBE_CALLBACK_PLACEHOLDER = b"{{CTF_OOB_URL}}"


class WebActiveProbeHotPathError(RuntimeError):
    """Stable operator-visible active-probe failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class _Issue:
    ordinal: int
    target_kind: str
    experiment_id: str
    run_id: str
    receipt_id: str
    report_artifact_id: str
    timeline_artifact_id: str
    setup_artifact_ids: tuple[str, ...]
    output_artifact_ids: tuple[str, ...]
    identity_epoch_sha256: str
    lineage_nonce_sha256: str
    callback_token_sha256: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "callback_token_sha256": self.callback_token_sha256,
            "experiment_id": self.experiment_id,
            "identity_epoch_sha256": self.identity_epoch_sha256,
            "lineage_nonce_sha256": self.lineage_nonce_sha256,
            "ordinal": self.ordinal,
            "output_artifact_ids": list(self.output_artifact_ids),
            "receipt_id": self.receipt_id,
            "report_artifact_id": self.report_artifact_id,
            "run_id": self.run_id,
            "setup_artifact_ids": list(self.setup_artifact_ids),
            "target_kind": self.target_kind,
            "timeline_artifact_id": self.timeline_artifact_id,
        }


@dataclass(frozen=True, slots=True)
class _IssueSecrets:
    issue: _Issue
    lineage_nonce: bytes
    callback_token: str | None


def _canonical_bytes(value: object) -> bytes:
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
        raise WebActiveProbeHotPathError(
            "active_probe_canonical_json_invalid"
        ) from error


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _remaining_seconds(deadline: float) -> int:
    remaining = int(deadline - time.monotonic())
    if remaining < 1:
        raise WebActiveProbeHotPathError(
            "active_probe_deadline_exceeded"
        )
    return remaining


def _driver_inputs(
    driver: WebActiveProbeDriver,
) -> tuple[WebImpactDriverInput, ...]:
    selected: dict[str, WebImpactDriverInput] = {}
    for step in (*driver.setup, driver.probe):
        for item in (step.route, step.body):
            if item is None:
                continue
            previous = selected.get(item.locator)
            if previous is not None and previous != item:
                raise WebActiveProbeHotPathError(
                    "active_probe_driver_input_locator_rebound"
                )
            selected[item.locator] = item
    return tuple(selected[key] for key in sorted(selected))


def _strict_report(payload: bytes) -> dict[str, object]:
    try:
        value = strict_json_loads(
            payload,
            max_bytes=WEB_ACTIVE_PROBE_MAX_REPORT_BYTES,
            max_depth=20,
        )
    except (StrictJSONError, UnicodeError, ValueError) as error:
        raise WebActiveProbeHotPathError(
            "active_probe_helper_report_invalid"
        ) from error
    if (
        type(value) is not dict
        or payload != _canonical_bytes(value)
    ):
        raise WebActiveProbeHotPathError(
            "active_probe_helper_report_not_canonical"
        )
    return value


def _snapshot_payload(
    root: Path,
    snapshot: object,
    *,
    maximum_bytes: int,
) -> bytes:
    try:
        return _read_snapshot(
            root,
            snapshot,
            maximum_bytes=maximum_bytes,
        )
    except Exception as error:
        raise WebActiveProbeHotPathError(
            "active_probe_snapshot_unavailable"
        ) from error


def _artifact_reference(
    *,
    artifact_id: str,
    destination: Path,
    state_root: Path,
    payload: bytes,
    run_id: str | None,
    role: str,
) -> ArtifactReference:
    return ArtifactReference(
        id=artifact_id,
        path=destination.relative_to(state_root).as_posix(),
        sha256=_sha256(payload),
        source_run_id=run_id,
        media_type=(
            "application/json"
            if destination.suffix == ".json"
            else "application/octet-stream"
        ),
        size=len(payload),
        extra={
            "context_visibility": "engine_private",
            "kind": role,
            "protocol": WEB_ACTIVE_PROBE_HOTPATH_PROTOCOL,
        },
    )


def _snapshot_artifact_reference(snapshot: object) -> ArtifactReference:
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
            "kind": f"web_active_probe_{snapshot.role}_snapshot",
            "protocol": WEB_ACTIVE_PROBE_HOTPATH_PROTOCOL,
            "source_locator": snapshot.source_locator,
        },
    )


def _read_workspace_artifact(
    client: object,
    workspace: Path,
    locator: str,
    *,
    maximum_bytes: int,
) -> bytes:
    try:
        reference = client.register_artifact(
            locator,
            maximum_bytes=maximum_bytes,
        )
        return read_bounded_regular(
            workspace,
            reference.locator,
            maximum_bytes=maximum_bytes,
            expected_sha256=reference.sha256,
            expected_size=reference.size_bytes,
        )
    except (OSError, SafeFileError, ValueError) as error:
        raise WebActiveProbeHotPathError(
            "active_probe_workspace_artifact_invalid"
        ) from error


def _target_binding(target: TargetRecord) -> dict[str, object]:
    return {
        "binding_sha256": web_impact_target_binding_sha256(target),
        "generation": target.generation,
        "kind": "allowlisted_http_origin_v1",
    }


def _response_output_names(
    mode: str,
    spec: dict[str, object],
    *,
    target_kind: str,
) -> tuple[str, ...]:
    if mode == "race":
        transport = spec["transport"]
        count = transport["concurrency"] * transport["attempts"]
        return tuple(
            f"response-{ordinal:04d}.bin"
            for ordinal in range(1, count + 1)
        )
    if target_kind == "vulnerable":
        return ("trigger-response.bin", "callback-01.bin")
    return ("trigger-response.bin",)


def _issue_documents(
    *,
    spec: dict[str, object],
    driver: WebActiveProbeDriver,
    attempt_id: str,
) -> tuple[_IssueSecrets, ...]:
    values: list[_IssueSecrets] = []
    target_kinds = (
        ("vulnerable",) * WEB_ACTIVE_PROBE_REPETITIONS
        + ("control",) * WEB_ACTIVE_PROBE_REPETITIONS
    )
    spec_sha256 = _sha256(
        _canonical_bytes(spec)
    )
    for ordinal, target_kind in enumerate(target_kinds, start=1):
        lineage_nonce = secrets.token_bytes(32)
        callback_token = (
            secrets.token_hex(16) if spec["mode"] == "oob" else None
        )
        epoch = _sha256(
            _canonical_bytes(
                {
                    "attempt_id": attempt_id,
                    "operator_spec_sha256": spec_sha256,
                    "ordinal": ordinal,
                    "target_kind": target_kind,
                    "transport_nonce_sha256": _sha256(
                        secrets.token_bytes(32)
                    ),
                }
            )
        )
        output_names = _response_output_names(
            spec["mode"],
            spec,
            target_kind=target_kind,
        )
        issue = _Issue(
            ordinal=ordinal,
            target_kind=target_kind,
            experiment_id=_new_id("E-web-active"),
            run_id=_new_id("WRUN-active"),
            receipt_id=_new_id("WREC-active"),
            report_artifact_id=_new_id("A-web-active-report"),
            timeline_artifact_id=_new_id(
                "A-web-active-timeline"
            ),
            setup_artifact_ids=tuple(
                _new_id("A-web-active-setup")
                for _step in driver.setup
            ),
            output_artifact_ids=tuple(
                _new_id("A-web-active-output")
                for _name in output_names
            ),
            identity_epoch_sha256=epoch,
            lineage_nonce_sha256=_sha256(lineage_nonce),
            callback_token_sha256=(
                _sha256(callback_token.encode("ascii"))
                if callback_token is not None
                else None
            ),
        )
        values.append(
            _IssueSecrets(
                issue=issue,
                lineage_nonce=lineage_nonce,
                callback_token=callback_token,
            )
        )
    return tuple(values)


def _request_document(
    *,
    attempt_id: str,
    issue: _Issue,
    spec_sha256: str,
    driver_sha256: str,
    target_id: str,
    target_binding: dict[str, object],
) -> dict[str, object]:
    return {
        "attempt_id": attempt_id,
        "authorities": {
            "automatic_submission_authorized": False,
            "candidate_authorized": False,
            "challenge_proof_satisfied": False,
            "flag_proven": False,
            "submission_authorized": False,
        },
        "driver_sha256": driver_sha256,
        "issue": issue.to_dict(),
        "operator_spec_sha256": spec_sha256,
        "protocol": WEB_ACTIVE_PROBE_HOTPATH_PROTOCOL,
        "schema_version": WEB_ACTIVE_PROBE_HOTPATH_SCHEMA_VERSION,
        "target": {
            **target_binding,
            "target_id": target_id,
        },
    }


def _active_argv(
    *,
    spec: dict[str, object],
    driver: WebActiveProbeDriver,
    url: str,
    body_path: str,
    callback_token: str | None,
    timeout_seconds: int,
) -> tuple[str, ...]:
    values = [
        WEB_ACTIVE_PROBE_HELPER_PATH,
        spec["mode"],
        url,
        "-X",
        driver.probe.method,
        "--session",
        spec["identity"]["role"],
        "--data-file",
        body_path,
        "--timeout",
        str(timeout_seconds),
    ]
    if spec["mode"] == "race":
        values.extend(
            (
                "--concurrency",
                str(spec["transport"]["concurrency"]),
                "--attempts",
                str(spec["transport"]["attempts"]),
            )
        )
    else:
        assert callback_token is not None
        values.extend(
            (
                "--callback-timeout",
                str(
                    spec["transport"][
                        "callback_timeout_seconds"
                    ]
                ),
                "--callback-token",
                callback_token,
            )
        )
    return tuple(values)


def _terminalize(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    attempt_id: str,
    error: BaseException,
) -> None:
    def apply(state: ChallengeState) -> None:
        attempts = state.extra.get(WEB_ACTIVE_PROBE_PREISSUES_KEY)
        if type(attempts) is not dict:
            return
        attempt = attempts.get(attempt_id)
        if (
            type(attempt) is dict
            and attempt.get("status") in {"issued", "running"}
        ):
            attempt["status"] = "failed"
            attempt["terminal"] = {
                "at": utc_now(),
                "error_type": type(error).__name__,
                "reason_code": "web_active_probe_interrupted",
            }

    try:
        engine.store.update(identity, apply)
    except BaseException as terminal_error:
        error.add_note(
            "Web active-probe terminalization failed: "
            f"{type(terminal_error).__name__}"
        )


def prove_web_active_probe(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    operator_spec_locator: str,
    driver_locator: str,
    hypothesis_ids: tuple[str, ...] = (),
    timeout_seconds: int = 900,
    _session_owned: bool = False,
) -> tuple[ChallengeState, dict[str, object]]:
    """Execute one exact race/OOB vulnerable3-control3 matrix."""

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
            return prove_web_active_probe(
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
    validate_web_active_probe_state_graph(state)
    if (
        state.category != "web"
        or state.schema_version < STATE_SCHEMA_VERSION
        or type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= 24 * 60 * 60
    ):
        raise EngineError(
            "Web active probe requires one schema-v2 Web challenge "
            "and timeout 1..86400"
        )
    if engine.config.runtime.image_digest is None:
        raise EngineError(
            "Web active probe requires a digest-pinned runtime image"
        )
    deadline = time.monotonic() + timeout_seconds
    manifest = inventory_challenge(engine.challenge_input(identity))
    if (
        state.metadata.get("source_manifest_sha256")
        != manifest.manifest_sha256
    ):
        raise EngineError(
            "Web active probe requires a current source manifest"
        )
    paths = engine.store.challenge_paths(identity)
    attempt_id = _new_id("web-active")
    root = ensure_private_directory(
        paths.artifacts / "web-active" / attempt_id
    )
    input_root = ensure_private_directory(root / "inputs")
    capture_root = ensure_private_directory(root / "captures")
    initial_client = engine.sandbox(
        state,
        network_policy_override=NetworkPolicy.deny_all(),
    )
    spec_snapshot = _snapshot_workspace_input(
        engine,
        state,
        client=initial_client,
        artifact_id=_new_id("A-web-active-spec"),
        locator=operator_spec_locator,
        destination=root / "operator-spec.json",
        role="operator_spec",
    )
    driver_snapshot = _snapshot_workspace_input(
        engine,
        state,
        client=initial_client,
        artifact_id=_new_id("A-web-active-driver"),
        locator=driver_locator,
        destination=root / "driver.json",
        role="driver",
    )
    spec_payload = _snapshot_payload(
        paths.root,
        spec_snapshot,
        maximum_bytes=WEB_ACTIVE_PROBE_MAX_SPEC_BYTES,
    )
    driver_payload = _snapshot_payload(
        paths.root,
        driver_snapshot,
        maximum_bytes=WEB_ACTIVE_PROBE_MAX_DRIVER_BYTES,
    )
    try:
        spec = parse_web_active_probe_operator_spec(spec_payload)
        driver = parse_web_active_probe_driver(
            driver_payload,
            operator_spec_payload=spec_payload,
        )
    except ValueError as error:
        raise EngineError(
            f"Web active-probe specification rejected: {error}"
        ) from error
    vulnerable = _target_for_id(
        engine,
        state,
        driver.vulnerable_target_id,
    )
    control = _target_for_id(
        engine,
        state,
        driver.control_target_id,
    )
    if (
        spec["source_manifest_sha256"] != manifest.manifest_sha256
        or spec["runtime_image_digest"]
        != engine.config.runtime.image_digest
        or spec["vulnerable_target"] != _target_binding(vulnerable)
        or spec["control_target"] != _target_binding(control)
    ):
        raise EngineError(
            "Web active-probe immutable environment binding changed"
        )
    if spec["mode"] == "oob" and driver.probe.body is None:
        raise EngineError("Web OOB probe body is unavailable")

    input_snapshots = []
    for position, item in enumerate(
        _driver_inputs(driver),
        start=1,
    ):
        input_snapshots.append(
            _snapshot_workspace_input(
                engine,
                state,
                client=initial_client,
                artifact_id=_new_id("A-web-active-input"),
                locator=item.locator,
                destination=input_root
                / f"input-{position:04d}.bin",
                role="driver_input",
                expected_sha256=item.sha256,
                expected_size=item.size_bytes,
            )
        )
    snapshots_by_locator = {
        item.source_locator: item for item in input_snapshots
    }
    probe_body = _snapshot_payload(
        paths.root,
        snapshots_by_locator[driver.probe.body.locator],
        maximum_bytes=WEB_ACTIVE_PROBE_MAX_ARTIFACT_BYTES,
    )
    if (
        spec["mode"] == "oob"
        and probe_body.count(
            WEB_ACTIVE_PROBE_CALLBACK_PLACEHOLDER
        )
        != 1
    ) or (
        spec["mode"] == "race"
        and WEB_ACTIVE_PROBE_CALLBACK_PLACEHOLDER in probe_body
    ):
        raise EngineError(
            "Web active-probe callback placeholder policy failed"
        )
    issues = _issue_documents(
        spec=spec,
        driver=driver,
        attempt_id=attempt_id,
    )
    all_issued_ids = {
        spec_snapshot.artifact_id,
        driver_snapshot.artifact_id,
        *(item.artifact_id for item in input_snapshots),
        *(
            value
            for issued in issues
            for value in (
                issued.issue.experiment_id,
                issued.issue.run_id,
                issued.issue.receipt_id,
                issued.issue.report_artifact_id,
                issued.issue.timeline_artifact_id,
                *issued.issue.setup_artifact_ids,
                *issued.issue.output_artifact_ids,
            )
        ),
    }
    evaluation_artifact_id = _new_id("A-web-active-evaluation")
    fact_id = _new_id("F-web-active")
    progress_id = _new_id("P-web-active")
    all_issued_ids.update(
        {evaluation_artifact_id, fact_id, progress_id}
    )
    if (
        len(all_issued_ids)
        != (
            5
            + len(input_snapshots)
            + sum(
                5
                + len(item.issue.setup_artifact_ids)
                + len(item.issue.output_artifact_ids)
                for item in issues
            )
        )
        or _all_state_ids(state) & all_issued_ids
    ):
        raise EngineError(
            "Web active-probe preissued identifiers collide"
        )
    spec_sha256 = _sha256(spec_payload)
    driver_sha256 = _sha256(driver_payload)
    request_bindings: list[dict[str, object]] = []
    for issued in issues:
        target = (
            vulnerable
            if issued.issue.target_kind == "vulnerable"
            else control
        )
        document = _request_document(
            attempt_id=attempt_id,
            issue=issued.issue,
            spec_sha256=spec_sha256,
            driver_sha256=driver_sha256,
            target_id=target.id,
            target_binding=_target_binding(target),
        )
        run_paths = engine.store.create_run(
            identity,
            issued.issue.run_id,
            request=document,
            base_revision=state.revision,
        )
        payload = run_paths.request.read_bytes()
        request_bindings.append(
            {
                "path": run_paths.request.relative_to(
                    paths.root
                ).as_posix(),
                "sha256": _sha256(payload),
                "size_bytes": len(payload),
            }
        )
    preissue = {
        "authorities": {
            "automatic_submission_authorized": False,
            "candidate_authorized": False,
            "challenge_proof_satisfied": False,
            "executed_fact_authorized": False,
            "flag_proven": False,
            "submission_authorized": False,
        },
        "attempt_id": attempt_id,
        "base_revision": state.revision,
        "configuration_epoch": state.configuration_epoch,
        "control_target_id": control.id,
        "driver": driver_snapshot.to_dict(),
        "driver_sha256": driver_sha256,
        "evaluation_artifact_id": evaluation_artifact_id,
        "fact_id": fact_id,
        "input_snapshots": [
            item.to_dict() for item in input_snapshots
        ],
        "issues": [
            item.issue.to_dict() for item in issues
        ],
        "mode": spec["mode"],
        "operator_spec": spec_snapshot.to_dict(),
        "operator_spec_sha256": spec_sha256,
        "progress_id": progress_id,
        "protocol": WEB_ACTIVE_PROBE_HOTPATH_PROTOCOL,
        "request_bindings": request_bindings,
        "runtime_image_digest": engine.config.runtime.image_digest,
        "schema_version": WEB_ACTIVE_PROBE_HOTPATH_SCHEMA_VERSION,
        "source_manifest_sha256": manifest.manifest_sha256,
        "status": "issued",
        "terminal": None,
        "vulnerable_target_id": vulnerable.id,
    }
    preissue_sha256 = _sha256(_canonical_bytes(preissue))

    def verify_preissue() -> None:
        current = engine.store.load(identity, recover=False)
        if (
            current.configuration_epoch != state.configuration_epoch
            or current.metadata.get("source_manifest_sha256")
            != manifest.manifest_sha256
            or engine.config.runtime.image_digest
            != spec["runtime_image_digest"]
        ):
            raise EngineError(
                "Web active-probe environment changed"
            )
        for target_id, expected in (
            (vulnerable.id, spec["vulnerable_target"]),
            (control.id, spec["control_target"]),
        ):
            actual = _target_for_id(engine, current, target_id)
            if _target_binding(actual) != expected:
                raise EngineError(
                    "Web active-probe target binding changed"
                )
        for snapshot, maximum in (
            (spec_snapshot, WEB_ACTIVE_PROBE_MAX_SPEC_BYTES),
            (driver_snapshot, WEB_ACTIVE_PROBE_MAX_DRIVER_BYTES),
            *(
                (
                    item,
                    WEB_ACTIVE_PROBE_MAX_ARTIFACT_BYTES,
                )
                for item in input_snapshots
            ),
        ):
            _snapshot_payload(
                paths.root,
                snapshot,
                maximum_bytes=maximum,
            )
        for issued, binding in zip(
            issues,
            request_bindings,
            strict=True,
        ):
            payload = read_bounded_regular(
                paths.root,
                binding["path"],
                maximum_bytes=256 * 1024,
                expected_sha256=binding["sha256"],
                expected_size=binding["size_bytes"],
            )
            document = strict_json_loads(
                payload,
                max_bytes=256 * 1024,
                max_depth=16,
            )
            if (
                type(document) is not dict
                or document.get("run_id") != issued.issue.run_id
                or document.get("base_revision") != state.revision
                or document.get("contest_id") != identity.contest_id
                or document.get("category") != identity.category
                or document.get("challenge_id") != identity.challenge_id
                or document.get("attempt_id") != attempt_id
                or document.get("protocol")
                != WEB_ACTIVE_PROBE_HOTPATH_PROTOCOL
                or document.get("operator_spec_sha256")
                != spec_sha256
                or document.get("driver_sha256") != driver_sha256
                or document.get("issue") != issued.issue.to_dict()
                or document.get("target")
                != {
                    **_target_binding(
                        vulnerable
                        if issued.issue.target_kind == "vulnerable"
                        else control
                    ),
                    "target_id": (
                        vulnerable.id
                        if issued.issue.target_kind == "vulnerable"
                        else control.id
                    ),
                }
            ):
                raise EngineError(
                    "Web active-probe request rebound"
                )

    reserved_ids = _all_state_ids(state)

    def commit_preissue(current: ChallengeState) -> None:
        if (
            current.revision != state.revision
            or current.configuration_epoch
            != state.configuration_epoch
            or _all_state_ids(current) != reserved_ids
        ):
            raise EngineError(
                "Web active-probe state changed before preissue"
            )
        root_value = current.extra.setdefault(
            WEB_ACTIVE_PROBE_PREISSUES_KEY,
            {},
        )
        if type(root_value) is not dict or any(
            type(item) is dict
            and item.get("status") in {"issued", "running"}
            for item in root_value.values()
        ):
            raise EngineError(
                "another Web active probe is already active"
            )
        root_value[attempt_id] = copy.deepcopy(preissue)

    committed = engine.store.update(
        identity,
        commit_preissue,
        expected_revision=state.revision,
        pre_replace_guard=verify_preissue,
    )
    try:
        persisted = committed.extra[
            WEB_ACTIVE_PROBE_PREISSUES_KEY
        ][attempt_id]
        if (
            persisted != preissue
            or _sha256(_canonical_bytes(persisted))
            != preissue_sha256
        ):
            raise EngineError(
                "Web active-probe preissue was not durable"
            )

        def mark_running(current: ChallengeState) -> None:
            attempt = current.extra[
                WEB_ACTIVE_PROBE_PREISSUES_KEY
            ][attempt_id]
            if attempt.get("status") != "issued":
                raise EngineError(
                    "Web active-probe preissue is not executable"
                )
            attempt["status"] = "running"

        engine.store.update(
            identity,
            mark_running,
            expected_revision=committed.revision,
            pre_replace_guard=verify_preissue,
        )
    except BaseException as error:
        _terminalize(engine, identity, attempt_id, error)
        raise

    records: list[dict[str, object]] = []
    experiments: list[Experiment] = []
    runs: list[RunReference] = []
    receipts: list[ExecutionReceipt] = []
    artifacts: list[ArtifactReference] = []
    try:
        for issued, request_binding in zip(
            issues,
            request_bindings,
            strict=True,
        ):
            verify_preissue()
            issue = issued.issue
            target_record = (
                vulnerable
                if issue.target_kind == "vulnerable"
                else control
            )
            network_target = NetworkTarget.parse(
                target_record.endpoint
            )
            policy = engine._network_policy_for_target(target_record)
            workspace = ensure_private_directory(
                paths.runtime
                / "web-active-live"
                / attempt_id
                / issue.run_id
            )
            if any(workspace.iterdir()):
                raise WebActiveProbeHotPathError(
                    "active_probe_workspace_not_fresh"
                )
            scope = ChallengeScope(
                contest_id=identity.contest_id,
                category=identity.category,
                challenge_id=identity.challenge_id,
                challenge_dir=engine.challenge_input(identity),
                work_dir=workspace,
            )
            reset_private_web_identity_state(
                scope,
                issue.identity_epoch_sha256,
            )
            if (
                private_web_identity_epoch_sha256(scope)
                != issue.identity_epoch_sha256
            ):
                raise WebActiveProbeHotPathError(
                    "active_probe_identity_epoch_not_fresh"
                )
            lineage_before = private_web_cookie_lineage_sha256(
                scope,
                spec["identity"]["role"],
                identity_epoch_sha256=issue.identity_epoch_sha256,
                lineage_nonce=issued.lineage_nonce,
            )
            client = engine.sandbox(
                engine.store.load(identity, recover=False),
                workspace_override=workspace,
                network_policy_override=policy,
            )
            client.initialize_workspace()
            setup_references: list[ArtifactReference] = []
            setup_manifest: list[dict[str, object]] = []
            for step, expected, artifact_id in zip(
                driver.setup,
                spec["setup"],
                issue.setup_artifact_ids,
                strict=True,
            ):
                route = validate_route_payload(
                    _snapshot_payload(
                        paths.root,
                        snapshots_by_locator[step.route.locator],
                        maximum_bytes=(
                            WEB_ACTIVE_PROBE_MAX_ARTIFACT_BYTES
                        ),
                    )
                )
                body_path = None
                if step.body is not None:
                    destination = (
                        workspace
                        / f"setup-{step.ordinal:02d}-body.bin"
                    )
                    _copy_snapshot_to_workspace(
                        paths.root,
                        snapshots_by_locator[step.body.locator],
                        destination,
                    )
                    body_path = (
                        f"/work/{destination.name}"
                    )
                engine._wait_for_remote_command_start(
                    engine.store.load(identity, recover=False),
                    network_target,
                )
                result = client.run(
                    CommandSpec(
                        argv=_helper_argv(
                            step=step,
                            url=_target_origin(target_record)
                            + route,
                            body_path=body_path,
                        ),
                        timeout_seconds=min(
                            step.timeout_seconds,
                            _remaining_seconds(deadline),
                        ),
                        summary_bytes=0,
                        network_target=network_target,
                        resource_request=ResourceVector(
                            cpu=1,
                            memory_mib=2 * 1024,
                            network=1,
                        ),
                    )
                )
                if (
                    result.status != "completed"
                    or result.exit_code != 0
                    or result.timed_out is not False
                    or result.orchestration_error is not None
                ):
                    raise WebActiveProbeHotPathError(
                        f"active_probe_setup_{step.ordinal}_failed"
                    )
                metadata = _read_workspace_artifact(
                    client,
                    workspace,
                    "web/response.json",
                    maximum_bytes=4 * 1024 * 1024,
                )
                status, truncated = _helper_metadata(
                    metadata,
                    channel="http",
                )
                response_destination = (
                    capture_root
                    / f"{artifact_id}.bin"
                )
                response = _artifact_bytes(
                    engine,
                    state,
                    client,
                    locator="web/body.bin",
                    destination=response_destination,
                    maximum_bytes=(
                        WEB_ACTIVE_PROBE_MAX_ARTIFACT_BYTES
                    ),
                    workspace_root=workspace,
                )
                signature = expected["expected_response"]
                if (
                    truncated
                    or status != signature["status"]
                    or _sha256(response)
                    != signature["body_sha256"]
                    or len(response)
                    != signature["body_size_bytes"]
                ):
                    raise WebActiveProbeHotPathError(
                        f"active_probe_setup_{step.ordinal}_oracle_failed"
                    )
                reference = _artifact_reference(
                    artifact_id=artifact_id,
                    destination=response_destination,
                    state_root=paths.root,
                    payload=response,
                    run_id=issue.run_id,
                    role="web_active_probe_setup_response",
                )
                setup_references.append(reference)
                setup_manifest.append(
                    {
                        "artifact_id": reference.id,
                        "sha256": reference.sha256,
                        "size_bytes": reference.size,
                        "status": status,
                    }
                )
            probe_route = validate_route_payload(
                _snapshot_payload(
                    paths.root,
                    snapshots_by_locator[
                        driver.probe.route.locator
                    ],
                    maximum_bytes=(
                        WEB_ACTIVE_PROBE_MAX_ARTIFACT_BYTES
                    ),
                )
            )
            probe_body_destination = (
                workspace / "active-probe-body.bin"
            )
            _copy_snapshot_to_workspace(
                paths.root,
                snapshots_by_locator[
                    driver.probe.body.locator
                ],
                probe_body_destination,
            )
            active_timeout = min(
                driver.probe.timeout_seconds,
                _remaining_seconds(deadline),
            )
            engine._wait_for_remote_command_start(
                engine.store.load(identity, recover=False),
                network_target,
            )
            started = time.monotonic()
            result = client.run(
                CommandSpec(
                    argv=_active_argv(
                        spec=spec,
                        driver=driver,
                        url=_target_origin(target_record)
                        + probe_route,
                        body_path="/work/active-probe-body.bin",
                        callback_token=issued.callback_token,
                        timeout_seconds=active_timeout,
                    ),
                    timeout_seconds=active_timeout,
                    summary_bytes=0,
                    network_target=network_target,
                    resource_request=ResourceVector(
                        cpu=(
                            min(
                                4,
                                spec["transport"]["concurrency"],
                            )
                            if spec["mode"] == "race"
                            else 1
                        ),
                        memory_mib=2 * 1024,
                        network=1,
                    ),
                )
            )
            wall_seconds = time.monotonic() - started
            if (
                result.status != "completed"
                or result.exit_code != 0
                or result.timed_out is not False
                or result.orchestration_error is not None
            ):
                raise WebActiveProbeHotPathError(
                    "active_probe_helper_failed"
                )
            report_payload = _read_workspace_artifact(
                client,
                workspace,
                "web-active/report.json",
                maximum_bytes=WEB_ACTIVE_PROBE_MAX_REPORT_BYTES,
            )
            report = _strict_report(report_payload)
            timeline_payload = _read_workspace_artifact(
                client,
                workspace,
                "web-active/timeline.json",
                maximum_bytes=4 * 1024 * 1024,
            )
            classified = classify_web_active_probe_report(
                spec,
                report,
                target_kind=issue.target_kind,
            )
            output_names = _response_output_names(
                spec["mode"],
                spec,
                target_kind=issue.target_kind,
            )
            if report.get("artifact_names") != list(output_names):
                raise WebActiveProbeHotPathError(
                    "active_probe_output_manifest_rebound"
                )
            output_references: list[ArtifactReference] = []
            for name, artifact_id in zip(
                output_names,
                issue.output_artifact_ids,
                strict=True,
            ):
                destination = capture_root / f"{artifact_id}.bin"
                payload = _artifact_bytes(
                    engine,
                    state,
                    client,
                    locator=f"web-active/{name}",
                    destination=destination,
                    maximum_bytes=(
                        WEB_ACTIVE_PROBE_MAX_ARTIFACT_BYTES
                    ),
                    workspace_root=workspace,
                )
                reference = _artifact_reference(
                    artifact_id=artifact_id,
                    destination=destination,
                    state_root=paths.root,
                    payload=payload,
                    run_id=issue.run_id,
                    role="web_active_probe_output",
                )
                output_references.append(reference)
            if spec["mode"] == "race":
                responses = report["responses"]
                for response, reference in zip(
                    responses,
                    output_references,
                    strict=True,
                ):
                    if (
                        response["body_sha256"] != reference.sha256
                        or response["body_size_bytes"]
                        != reference.size
                    ):
                        raise WebActiveProbeHotPathError(
                            "active_probe_response_bytes_rebound"
                        )
            else:
                trigger = report["trigger"]
                if (
                    trigger["body_sha256"]
                    != output_references[0].sha256
                    or trigger["body_size_bytes"]
                    != output_references[0].size
                ):
                    raise WebActiveProbeHotPathError(
                        "active_probe_trigger_bytes_rebound"
                    )
                callbacks = report["callbacks"]
                for callback, reference in zip(
                    callbacks,
                    output_references[1:],
                    strict=True,
                ):
                    if (
                        callback["body_sha256"] != reference.sha256
                        or callback["body_size_bytes"]
                        != reference.size
                    ):
                        raise WebActiveProbeHotPathError(
                            "active_probe_callback_bytes_rebound"
                        )
            report_destination = (
                capture_root / f"{issue.report_artifact_id}.json"
            )
            persisted_report = _artifact_bytes(
                engine,
                state,
                client,
                locator="web-active/report.json",
                destination=report_destination,
                maximum_bytes=WEB_ACTIVE_PROBE_MAX_REPORT_BYTES,
                workspace_root=workspace,
            )
            timeline_destination = (
                capture_root
                / f"{issue.timeline_artifact_id}.json"
            )
            persisted_timeline = _artifact_bytes(
                engine,
                state,
                client,
                locator="web-active/timeline.json",
                destination=timeline_destination,
                maximum_bytes=4 * 1024 * 1024,
                workspace_root=workspace,
            )
            report_reference = _artifact_reference(
                artifact_id=issue.report_artifact_id,
                destination=report_destination,
                state_root=paths.root,
                payload=persisted_report,
                run_id=issue.run_id,
                role="web_active_probe_report",
            )
            timeline_reference = _artifact_reference(
                artifact_id=issue.timeline_artifact_id,
                destination=timeline_destination,
                state_root=paths.root,
                payload=persisted_timeline,
                run_id=issue.run_id,
                role="web_active_probe_timeline",
            )
            lineage_after = private_web_cookie_lineage_sha256(
                scope,
                spec["identity"]["role"],
                identity_epoch_sha256=issue.identity_epoch_sha256,
                lineage_nonce=issued.lineage_nonce,
            )
            record = {
                **classified,
                "artifact_bindings": {
                    "outputs": [
                        {
                            "artifact_id": item.id,
                            "path": item.path,
                            "sha256": item.sha256,
                            "size_bytes": item.size,
                        }
                        for item in output_references
                    ],
                    "report": {
                        "artifact_id": report_reference.id,
                        "path": report_reference.path,
                        "sha256": report_reference.sha256,
                        "size_bytes": report_reference.size,
                    },
                    "setup": setup_manifest,
                    "timeline": {
                        "artifact_id": timeline_reference.id,
                        "path": timeline_reference.path,
                        "sha256": timeline_reference.sha256,
                        "size_bytes": timeline_reference.size,
                    },
                },
                "cookie_lineage_after_sha256": lineage_after,
                "cookie_lineage_before_sha256": lineage_before,
                "experiment_id": issue.experiment_id,
                "identity_epoch_sha256": (
                    issue.identity_epoch_sha256
                ),
                "lineage_nonce_sha256": (
                    issue.lineage_nonce_sha256
                ),
                "ordinal": issue.ordinal,
                "receipt_id": issue.receipt_id,
                "report_sha256": report_reference.sha256,
                "request_sha256": request_binding["sha256"],
                "run_id": issue.run_id,
                "setup_manifest_sha256": _sha256(
                    _canonical_bytes(setup_manifest)
                ),
                "target": {
                    **_target_binding(target_record),
                    "target_id": target_record.id,
                },
                "target_kind": issue.target_kind,
                "timeline_sha256": timeline_reference.sha256,
            }
            engine.store.write_run_result(
                identity,
                issue.run_id,
                {
                    "protocol": WEB_ACTIVE_PROBE_HOTPATH_PROTOCOL,
                    "receipt_id": issue.receipt_id,
                    "record_sha256": _sha256(
                        _canonical_bytes(record)
                    ),
                },
            )
            engine.store.write_run_validation(
                identity,
                issue.run_id,
                {
                    "ok": classified["passed"],
                    "operator_spec_sha256": spec_sha256,
                    "protocol": WEB_ACTIVE_PROBE_HOTPATH_PROTOCOL,
                },
            )
            run_paths = engine.store.run_paths(
                identity,
                issue.run_id,
            )
            sidecars: dict[str, dict[str, object]] = {}
            for sidecar_name, sidecar_path in (
                ("result", run_paths.result),
                ("validation", run_paths.validation),
            ):
                sidecar_payload = sidecar_path.read_bytes()
                if not 1 <= len(sidecar_payload) <= 256 * 1024:
                    raise WebActiveProbeHotPathError(
                        "active_probe_run_sidecar_size_invalid"
                    )
                sidecars[sidecar_name] = {
                    "path": sidecar_path.relative_to(
                        paths.root
                    ).as_posix(),
                    "sha256": _sha256(sidecar_payload),
                    "size_bytes": len(sidecar_payload),
                }
            experiment = Experiment(
                id=issue.experiment_id,
                hypothesis_ids=list(hypothesis_ids),
                command=(
                    "engine-owned bounded Web active-probe helper"
                ),
                expected_observation=(
                    "exact active-probe oracle for this target kind"
                ),
                keep_if="deterministic oracle passes",
                drop_if="transport or deterministic oracle rejects",
                timeout_seconds=timeout_seconds,
                resource_class="heavy",
                # The engine-owned six-run graph is the proof boundary.  Each
                # individual replay remains a typed probe and therefore does
                # not claim a standalone candidate ProofRecipe.
                kind=ExperimentKind.PROBE,
                status=ExperimentStatus.COMPLETED,
                result={"web_active_probe": copy.deepcopy(record)},
                artifact_ids=[
                    item.id
                    for item in (
                        *setup_references,
                        *output_references,
                        report_reference,
                        timeline_reference,
                    )
                ],
                evidence_run_ids=[issue.run_id],
                evidence_receipt_ids=[issue.receipt_id],
                evaluation_reason=(
                    "web_active_probe_oracle_passed"
                    if classified["passed"]
                    else "web_active_probe_oracle_rejected"
                ),
                evaluated_at=utc_now(),
                extra={
                    "engine_executor": (
                        WEB_ACTIVE_PROBE_HOTPATH_PROTOCOL
                    ),
                    "web_active_probe": {
                        "attempt_id": attempt_id,
                        "ordinal": issue.ordinal,
                        "record_sha256": _sha256(
                            _canonical_bytes(record)
                        ),
                    },
                },
            )
            run = RunReference(
                id=issue.run_id,
                base_revision=state.revision,
                status=RunStatus.COMPLETED,
                request_path=run_paths.request.relative_to(
                    paths.root
                ).as_posix(),
                result_path=run_paths.result.relative_to(
                    paths.root
                ).as_posix(),
                validation_path=run_paths.validation.relative_to(
                    paths.root
                ).as_posix(),
                role="web_active_probe",
                origin=RunOrigin.OPERATOR_TOOL,
                configuration_epoch=state.configuration_epoch,
                extra={
                    "web_active_probe": copy.deepcopy(record),
                    "web_active_probe_sidecars": sidecars,
                },
            )
            receipt = ExecutionReceipt(
                id=issue.receipt_id,
                experiment_id=issue.experiment_id,
                run_id=issue.run_id,
                outcome=ReceiptOutcome.SUCCEEDED,
                exit_code=0,
                wall_seconds=wall_seconds,
                preview="",
                extra={
                    "web_active_probe": {
                        "record_sha256": _sha256(
                            _canonical_bytes(record)
                        ),
                        "report_artifact_id": report_reference.id,
                        "timeline_artifact_id": (
                            timeline_reference.id
                        ),
                    }
                },
            )
            records.append(record)
            experiments.append(experiment)
            runs.append(run)
            receipts.append(receipt)
            artifacts.extend(
                (
                    *setup_references,
                    *output_references,
                    report_reference,
                    timeline_reference,
                )
            )

        evaluation = evaluate_web_active_probe_records(
            operator_spec_sha256=spec_sha256,
            mode=spec["mode"],
            records=tuple(records),
        )
        evaluation_payload = _canonical_bytes(evaluation)
        evaluation_path = root / "evaluation.json"
        atomic_write_bytes(
            evaluation_path,
            evaluation_payload,
            mode=0o400,
        )
        evaluation_reference = _artifact_reference(
            artifact_id=evaluation_artifact_id,
            destination=evaluation_path,
            state_root=paths.root,
            payload=evaluation_payload,
            run_id=runs[-1].id,
            role="web_active_probe_evaluation",
        )
        shared_artifacts = [
            _snapshot_artifact_reference(spec_snapshot),
            _snapshot_artifact_reference(driver_snapshot),
            *(
                _snapshot_artifact_reference(item)
                for item in input_snapshots
            ),
            evaluation_reference,
        ]
        final_base = engine.store.load(identity, recover=False)
        expected_existing_ids = _all_state_ids(final_base)
        graph = {
            "authorities": {
                "automatic_submission_authorized": False,
                "candidate_authorized": False,
                "challenge_proof_satisfied": False,
                "flag_proven": False,
                "submission_authorized": False,
                "web_active_probe_dependency_proven": (
                    evaluation["confirmed"]
                ),
            },
            "attempt_id": attempt_id,
            "committed_state_revision": final_base.revision + 1,
            "evaluation": copy.deepcopy(evaluation),
            "evaluation_artifact_id": evaluation_artifact_id,
            "identity": identity.to_dict(),
            "mode": spec["mode"],
            "operator_spec_sha256": spec_sha256,
            "preissue_sha256": preissue_sha256,
            "protocol": WEB_ACTIVE_PROBE_HOTPATH_PROTOCOL,
            "records": copy.deepcopy(records),
            "schema_version": (
                WEB_ACTIVE_PROBE_HOTPATH_SCHEMA_VERSION
            ),
            "source_state_revision": final_base.revision,
        }
        graph_sha256 = _sha256(_canonical_bytes(graph))
        fact = (
            Fact(
                id=fact_id,
                statement=(
                    "A bounded Web "
                    f"{spec['mode']} impact was reproduced in three "
                    "vulnerable replays and rejected by three exact "
                    "patched/non-vulnerable controls; this is not flag proof"
                ),
                provenance=Provenance.EXECUTED,
                challenge_id=state.challenge_id,
                source_run_id=runs[-1].id,
                artifact_id=evaluation_reference.id,
                locator=evaluation_reference.path,
                extra={
                    "web_active_probe": {
                        "attempt_id": attempt_id,
                        "evaluation_sha256": evaluation[
                            "evaluation_sha256"
                        ],
                        "graph_sha256": graph_sha256,
                        "mode": spec["mode"],
                        "protocol": (
                            WEB_ACTIVE_PROBE_HOTPATH_PROTOCOL
                        ),
                    }
                },
            )
            if evaluation["confirmed"]
            else None
        )
        progress = (
            ProgressMarker(
                id=progress_id,
                statement=(
                    f"Web {spec['mode']} active-probe gate passed; "
                    "candidate remains unproved and unsubmitted"
                ),
                run_id=runs[-1].id,
                artifact_ids=[evaluation_reference.id],
                extra={
                    "adapter_marker": (
                        "web_active_probe_confirmed"
                    ),
                    "automatic_submission_authorized": False,
                    "evaluation_sha256": evaluation[
                        "evaluation_sha256"
                    ],
                    "graph_sha256": graph_sha256,
                    "protocol": (
                        WEB_ACTIVE_PROBE_HOTPATH_PROTOCOL
                    ),
                },
            )
            if evaluation["confirmed"]
            else None
        )

        def verify_final() -> None:
            verify_preissue()
            for reference in (*artifacts, *shared_artifacts):
                read_bounded_regular(
                    paths.root,
                    reference.path,
                    maximum_bytes=max(1, reference.size or 0),
                    expected_sha256=reference.sha256,
                    expected_size=reference.size,
                )
            for run in runs:
                sidecars = run.extra["web_active_probe_sidecars"]
                for binding in sidecars.values():
                    read_bounded_regular(
                        paths.root,
                        binding["path"],
                        maximum_bytes=256 * 1024,
                        expected_sha256=binding["sha256"],
                        expected_size=binding["size_bytes"],
                    )

        def commit_final(current: ChallengeState) -> None:
            if (
                current.revision != final_base.revision
                or current.configuration_epoch
                != state.configuration_epoch
                or _all_state_ids(current) != expected_existing_ids
            ):
                raise EngineError(
                    "Web active-probe state changed before commit"
                )
            attempt = current.extra[
                WEB_ACTIVE_PROBE_PREISSUES_KEY
            ][attempt_id]
            if (
                attempt.get("status") != "running"
                or attempt.get("terminal") is not None
            ):
                raise EngineError(
                    "Web active-probe preissue is no longer running"
                )
            current.experiments.extend(copy.deepcopy(experiments))
            current.runs.extend(copy.deepcopy(runs))
            current.receipts.extend(copy.deepcopy(receipts))
            current.artifacts.extend(copy.deepcopy(artifacts))
            current.artifacts.extend(copy.deepcopy(shared_artifacts))
            if fact is not None:
                current.facts.append(copy.deepcopy(fact))
            if progress is not None:
                current.progress_markers.append(
                    copy.deepcopy(progress)
                )
            attempt["status"] = "completed"
            attempt["terminal"] = {
                "at": utc_now(),
                "confirmed": evaluation["confirmed"],
                "evaluation_sha256": evaluation[
                    "evaluation_sha256"
                ],
                "graph_sha256": graph_sha256,
            }
            journal = current.extra.setdefault(
                WEB_ACTIVE_PROBE_GRAPHS_KEY,
                {},
            )
            if type(journal) is not dict or attempt_id in journal:
                raise EngineError(
                    "Web active-probe graph journal collision"
                )
            journal[attempt_id] = {
                "graph": copy.deepcopy(graph),
                "graph_sha256": graph_sha256,
                "protocol": WEB_ACTIVE_PROBE_HOTPATH_PROTOCOL,
                "schema_version": (
                    WEB_ACTIVE_PROBE_HOTPATH_SCHEMA_VERSION
                ),
            }

        committed_final = engine.store.update(
            identity,
            commit_final,
            expected_revision=final_base.revision,
            pre_replace_guard=verify_final,
        )
        validate_web_active_probe_state_graph(committed_final)
        return committed_final, evaluation
    except BaseException as error:
        _terminalize(engine, identity, attempt_id, error)
        raise


__all__ = [
    "WEB_ACTIVE_PROBE_GRAPHS_KEY",
    "WEB_ACTIVE_PROBE_HOTPATH_PROTOCOL",
    "WEB_ACTIVE_PROBE_HOTPATH_SCHEMA_VERSION",
    "WEB_ACTIVE_PROBE_PREISSUES_KEY",
    "WebActiveProbeHotPathError",
    "prove_web_active_probe",
]
