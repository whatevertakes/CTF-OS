#!/usr/bin/env python3
"""Run the Web 3+3 impact hot path against local Docker targets.

This release smoke uses the public ``ChallengeEngine.prove_web_impact`` entry
point, the exact digest-pinned CTF-OS image, and two ephemeral HTTP targets on
one dedicated Docker ``--internal`` network.  The targets enforce per-role
cookie persistence and separation.  No external internet, model call, flag
candidate, submission, automatic challenge selection, or fake sandbox is used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import subprocess
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any

from ctf_os.capabilities import inspect_pinned_capabilities
from ctf_os.config import (
    EngineConfig,
    ResourceConfig,
    RuntimeConfig,
)
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.web_impact import WEB_IDENTITY_ROLES
from ctf_os.engine.web_impact_driver import (
    WebImpactDriverInput,
    WebImpactDriverManifest,
    WebImpactDriverStep,
    web_impact_target_binding_sha256,
    web_impact_trace_contract_sha256,
)
from ctf_os.engine.web_impact_execution import (
    WEB_IMPACT_ALLOWLISTED_TARGET_KIND,
    WEB_IMPACT_OPERATOR_SPEC_PROTOCOL,
)
from ctf_os.engine.web_impact_state import (
    validate_web_impact_state_graph,
)
from ctf_os.images import validate_image_digest
from ctf_os.models import (
    ChallengeIdentity,
    Provenance,
    ReceiptOutcome,
    RunStatus,
)
from ctf_os.sandbox.files import read_bounded_regular
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.stages.ingest import inventory_challenge
from ctf_os.store.atomic import StrictJSONError, strict_json_loads


TARGET_PORT = 18080
VULNERABLE_BODY = b"vulnerable-impact-confirmed"
CONTROL_BODY = b"patched-control-denied"
COOKIE_VALUES = (
    b"user-private-cookie-value",
    b"admin-private-cookie-value",
    b"attacker-private-cookie-value",
)
ROUTES = (
    ("user", "http", "/login/user"),
    ("admin", "browser", "/login/admin"),
    ("attacker", "http", "/login/attacker"),
    ("user", "http", "/use/user"),
    ("admin", "browser", "/use/admin"),
    ("attacker", "http", "/extract"),
)
TARGET_AUDIT_LOG_MAX_BYTES = 65_536
TARGET_AUDIT_LOG_MAX_EVENTS = 64
PHYSICAL_JSON_MAX_BYTES = 256 * 1024
PHYSICAL_ARTIFACT_MAX_BYTES = 32 * 1024 * 1024
TARGET_SERVER_SOURCE = r"""
from __future__ import annotations

import json
import sys
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MODE = sys.argv[1]
PORT = int(sys.argv[2])
TOKENS = {
    "user": "user-private-cookie-value",
    "admin": "admin-private-cookie-value",
    "attacker": "attacker-private-cookie-value",
}
VULNERABLE_BODY = b"vulnerable-impact-confirmed"
CONTROL_BODY = b"patched-control-denied"


def cookie_names(value: str | None) -> set[str]:
    parsed = SimpleCookie()
    if value:
        parsed.load(value)
    return set(parsed)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_GET(self) -> None:
        names = cookie_names(self.headers.get("Cookie"))
        accepted = True
        status = 200
        body = b"ok"
        set_cookie = None
        if self.path == "/health":
            body = b"healthy"
        elif self.path.startswith("/login/"):
            role = self.path.removeprefix("/login/")
            accepted = role in TOKENS and not names
            if accepted:
                set_cookie = (
                    f"role_{role}={TOKENS[role]}; Path=/; "
                    "HttpOnly; SameSite=Lax"
                )
                body = f"logged-in:{role}".encode("ascii")
        elif self.path.startswith("/use/"):
            role = self.path.removeprefix("/use/")
            accepted = (
                role in TOKENS
                and names == {f"role_{role}"}
            )
            body = f"used:{role}".encode("ascii")
        elif self.path == "/extract":
            accepted = names == {"role_attacker"}
            if accepted and MODE == "vulnerable":
                body = VULNERABLE_BODY
            elif accepted:
                status = 403
                body = CONTROL_BODY
        else:
            accepted = False
            status = 404
            body = b"not-found"
        if not accepted:
            status = 409
            body = b"session-separation-failed"

        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        if set_cookie is not None:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()
        self.wfile.write(body)
        print(
            json.dumps(
                {
                    "accepted": accepted,
                    "cookie_names": sorted(names),
                    "mode": MODE,
                    "path": self.path,
                    "status": status,
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            flush=True,
        )


server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
server.daemon_threads = True
server.serve_forever()
""".lstrip()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Require the Web impact 3-vulnerable + 3-control gate to pass "
            "through the exact pinned image on an internal Docker network."
        )
    )
    parser.add_argument(
        "--image-digest",
        required=True,
        help="exact local sha256:<64 lowercase hex> Docker image ID",
    )
    return parser.parse_args()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(value: object) -> bytes:
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


def _docker(
    argv: tuple[str, ...],
    *,
    timeout: int = 120,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ("docker", *argv),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        text=True,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        detail = result.stderr.strip()[:4096]
        raise RuntimeError(
            f"docker {' '.join(argv[:3])} failed: {detail}"
        )
    return result


def _start_target(
    *,
    image_digest: str,
    network: str,
    name: str,
    alias: str,
    mode: str,
    server_path: Path,
) -> None:
    mount = (
        f"type=bind,src={server_path},"
        "dst=/opt/ctfos-release/web-target.py,readonly"
    )
    _docker(
        (
            "run",
            "--detach",
            "--name",
            name,
            "--label",
            "ctfos.release_smoke=web-impact",
            "--network",
            network,
            "--network-alias",
            alias,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "64",
            "--memory",
            "256m",
            "--cpus",
            "0.5",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=16m",
            "--mount",
            mount,
            "--entrypoint",
            "/usr/bin/python3",
            image_digest,
            "/opt/ctfos-release/web-target.py",
            mode,
            str(TARGET_PORT),
        )
    )
    details = json.loads(
        _docker(("container", "inspect", name)).stdout
    )
    if (
        type(details) is not list
        or len(details) != 1
        or details[0].get("Image") != image_digest
        or details[0].get("State", {}).get("Running") is not True
    ):
        raise AssertionError(
            f"{mode} target did not start from the pinned image"
        )


def _wait_healthy(name: str) -> None:
    command = (
        "import urllib.request;"
        f"r=urllib.request.urlopen('http://127.0.0.1:{TARGET_PORT}/health',"
        "timeout=2);"
        "assert r.status == 200 and r.read() == b'healthy'"
    )
    deadline = time.monotonic() + 30
    last_error = ""
    while time.monotonic() < deadline:
        result = _docker(
            (
                "exec",
                name,
                "/usr/bin/python3",
                "-c",
                command,
            ),
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            return
        last_error = result.stderr.strip()[:1024]
        time.sleep(0.1)
    raise RuntimeError(f"target {name} was not healthy: {last_error}")


def _parse_target_event_stream(
    payload: str,
    *,
    mode: str,
) -> list[dict[str, object]]:
    if len(payload.encode("utf-8")) > TARGET_AUDIT_LOG_MAX_BYTES:
        raise AssertionError(
            f"{mode} target audit log exceeds its byte limit"
        )

    def reject_duplicate_keys(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    def reject_nonfinite(value: str) -> object:
        raise ValueError(f"non-finite JSON value: {value}")

    decoder = json.JSONDecoder(
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_nonfinite,
    )
    events: list[dict[str, object]] = []
    offset = 0
    while offset < len(payload):
        while offset < len(payload) and payload[offset].isspace():
            offset += 1
        if offset == len(payload):
            break
        try:
            value, end = decoder.raw_decode(payload, offset)
        except (json.JSONDecodeError, ValueError) as error:
            raise AssertionError(
                f"{mode} target audit log is not an exact JSON object stream"
            ) from error
        if type(value) is not dict:
            raise AssertionError(f"{mode} target audit is not an object")
        events.append(value)
        if len(events) > TARGET_AUDIT_LOG_MAX_EVENTS:
            raise AssertionError(
                f"{mode} target audit log exceeds its event limit"
            )
        offset = end
    return events


def _target_audit(name: str, mode: str) -> dict[str, object]:
    observed = _parse_target_event_stream(
        _docker(("logs", name), timeout=30).stdout,
        mode=mode,
    )
    events = [
        value for value in observed if value.get("path") != "/health"
    ]
    expected_paths = [route for _role, _channel, route in ROUTES]
    counts = Counter(
        str(event.get("path"))
        for event in events
    )
    if (
        len(events) != 18
        or counts != Counter({path: 3 for path in expected_paths})
        or any(event.get("accepted") is not True for event in events)
        or any(event.get("mode") != mode for event in events)
    ):
        raise AssertionError(
            f"{mode} target did not observe three exact isolated sessions: "
            + json.dumps(events, sort_keys=True)[:4096]
        )
    extract_statuses = {
        event.get("status")
        for event in events
        if event.get("path") == "/extract"
    }
    expected_status = 200 if mode == "vulnerable" else 403
    if extract_statuses != {expected_status}:
        raise AssertionError(
            f"{mode} target returned unexpected extract statuses"
        )
    return {
        "accepted_requests": len(events),
        "endpoint_counts": dict(sorted(counts.items())),
        "extract_status": expected_status,
    }


def _engine(root: Path, image_digest: str) -> ChallengeEngine:
    return ChallengeEngine(
        root,
        config=EngineConfig(
            workspace_root=root,
            resources=ResourceConfig(
                remote_command_min_interval_s=0.0,
            ),
            runtime=RuntimeConfig(
                image="ctf-os:core",
                image_digest=image_digest,
                network_default="none",
                command_timeout_s=60,
            ),
        ),
    )


def _physical_json(
    challenge_root: Path,
    relative: str,
    *,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
) -> tuple[bytes, dict[str, object]]:
    path = challenge_root / relative
    try:
        if expected_sha256 is None or expected_size is None:
            metadata = path.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size > PHYSICAL_JSON_MAX_BYTES
            ):
                raise ValueError("not a bounded regular file")
            initial = path.read_bytes()
            if expected_sha256 is None:
                expected_sha256 = _sha256(initial)
            if expected_size is None:
                expected_size = len(initial)
        payload = read_bounded_regular(
            challenge_root,
            relative,
            maximum_bytes=PHYSICAL_JSON_MAX_BYTES,
            expected_sha256=expected_sha256,
            expected_size=expected_size,
        )
        decoded = strict_json_loads(
            payload,
            max_bytes=PHYSICAL_JSON_MAX_BYTES,
            max_depth=32,
        )
    except (
        OSError,
        StrictJSONError,
        UnicodeError,
        ValueError,
    ) as error:
        raise AssertionError(
            f"Web impact physical JSON revalidation failed: {relative}"
        ) from error
    if type(decoded) is not dict:
        raise AssertionError(
            f"Web impact physical JSON is not an object: {relative}"
        )
    return payload, decoded


def _revalidate_physical_web_impact(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    evaluation_sha256: str,
    expected_replay_count: int,
) -> tuple[object, dict[str, int]]:
    """Reload state and verify every committed Web impact byte/sidecar."""

    state = engine.store.load(identity, recover=False)
    state.validate()
    validate_web_impact_state_graph(state)
    attempts = state.extra.get("web_impact_preissues")
    if type(attempts) is not dict or len(attempts) != 1:
        raise AssertionError(
            "Web impact release state must contain one exact attempt"
        )
    attempt = next(iter(attempts.values()))
    if (
        type(attempt) is not dict
        or attempt.get("status") != "completed"
        or type(attempt.get("terminal")) is not dict
        or attempt["terminal"].get("evaluation_sha256")
        != evaluation_sha256
        or attempt.get("runtime_image_digest")
        != engine.config.runtime.image_digest
        or inventory_challenge(
            engine.challenge_input(identity)
        ).manifest_sha256
        != attempt.get("source_manifest_sha256")
    ):
        raise AssertionError(
            "Web impact physical environment or terminal binding changed"
        )
    replays = attempt.get("replays")
    requests = attempt.get("canonical_requests")
    plan = attempt.get("execution_plan")
    plan_requests = (
        plan.get("requests") if type(plan) is dict else None
    )
    if (
        type(replays) is not list
        or type(requests) is not list
        or type(plan_requests) is not list
        or type(expected_replay_count) is not int
        or expected_replay_count < 1
        or len(replays) != expected_replay_count
        or len(requests) != expected_replay_count
        or len(plan_requests) != expected_replay_count
    ):
        raise AssertionError(
            "Web impact physical replay cohort is not exact 3+3"
        )
    run_ids = [item.get("run_id") for item in replays]
    receipt_ids = [item.get("receipt_id") for item in replays]
    if (
        any(type(value) is not str for value in run_ids)
        or len(set(run_ids)) != expected_replay_count
        or any(type(value) is not str for value in receipt_ids)
        or len(set(receipt_ids)) != expected_replay_count
    ):
        raise AssertionError(
            "Web impact physical replay identities are reused"
        )
    runs = {item.id: item for item in state.runs}
    receipts = {item.id: item for item in state.receipts}
    artifacts = {item.id: item for item in state.artifacts}
    expected_artifact_values: list[str] = []
    for key in ("operator_spec", "driver"):
        snapshot = attempt.get(key)
        if type(snapshot) is not dict:
            raise AssertionError(
                f"Web impact {key} snapshot is missing"
            )
        expected_artifact_values.append(str(snapshot.get("artifact_id")))
    snapshots = attempt.get("input_snapshots")
    if type(snapshots) is not list:
        raise AssertionError("Web impact input snapshots are missing")
    expected_artifact_values.extend(
        str(snapshot.get("artifact_id"))
        for snapshot in snapshots
        if type(snapshot) is dict
    )
    expected_state_ids = attempt.get("expected_state_ids")
    if type(expected_state_ids) is not dict:
        raise AssertionError("Web impact state IDs are missing")
    for value in expected_state_ids.values():
        if value in artifacts:
            expected_artifact_values.append(value)
    for replay in replays:
        if type(replay) is not dict:
            raise AssertionError("Web impact replay binding is invalid")
        for key in ("request_artifact_ids", "response_artifact_ids"):
            values = replay.get(key)
            if type(values) is not list:
                raise AssertionError(
                    "Web impact replay artifact IDs are invalid"
                )
            expected_artifact_values.extend(str(value) for value in values)
        expected_artifact_values.append(
            str(replay.get("trace_artifact_id"))
        )
    expected_artifact_ids = set(expected_artifact_values)
    if any(value not in artifacts for value in expected_artifact_ids):
        raise AssertionError(
            "Web impact committed artifact inventory is incomplete"
        )
    experiment_id = expected_state_ids.get("experiment_id")
    marked_artifacts = {
        item.id
        for item in state.artifacts
        if type(item.extra.get("web_impact_state")) is dict
        and item.extra["web_impact_state"].get("experiment_id")
        == experiment_id
    }
    if not marked_artifacts.issubset(expected_artifact_ids):
        raise AssertionError(
            "Web impact state contains an unbound committed artifact"
        )
    challenge_root = engine.store.challenge_paths(identity).root
    for artifact_id in sorted(expected_artifact_ids):
        artifact = artifacts[artifact_id]
        if (
            type(artifact.size) is not int
            or artifact.size < 0
            or artifact.size > PHYSICAL_ARTIFACT_MAX_BYTES
        ):
            raise AssertionError(
                "Web impact artifact size is outside release bounds"
            )
        try:
            read_bounded_regular(
                challenge_root,
                artifact.path,
                maximum_bytes=PHYSICAL_ARTIFACT_MAX_BYTES,
                expected_sha256=artifact.sha256,
                expected_size=artifact.size,
            )
        except (OSError, ValueError) as error:
            raise AssertionError(
                "Web impact committed artifact revalidation failed: "
                f"{artifact.id}"
            ) from error

    for replay, request_binding, plan_request in zip(
        replays,
        requests,
        plan_requests,
        strict=True,
    ):
        if (
            type(replay) is not dict
            or type(request_binding) is not dict
            or type(plan_request) is not dict
        ):
            raise AssertionError(
                "Web impact replay sidecar binding is invalid"
            )
        run_id = replay["run_id"]
        receipt_id = replay["receipt_id"]
        run = runs.get(run_id)
        receipt = receipts.get(receipt_id)
        run_root = f"runs/{run_id}"
        if (
            run is None
            or receipt is None
            or run.status is not RunStatus.COMPLETED
            or receipt.outcome is not ReceiptOutcome.SUCCEEDED
            or receipt.run_id != run_id
            or receipt.exit_code != 0
            or run.request_path != request_binding.get("path")
            or run.result_path != f"{run_root}/result.json"
            or run.validation_path != f"{run_root}/validation.json"
            or run.extra.get("transport_receipt_path")
            != f"{run_root}/web-impact-receipt.json"
            or receipt.extra.get("transport_receipt_path")
            != f"{run_root}/web-impact-receipt.json"
            or run.extra.get("request_sha256")
            != plan_request.get("request_sha256")
        ):
            raise AssertionError(
                "Web impact canonical run/receipt binding changed"
            )
        _request_payload, request_document = _physical_json(
            challenge_root,
            run.request_path,
            expected_sha256=request_binding.get("sha256"),
            expected_size=request_binding.get("size_bytes"),
        )
        if request_document != request_binding.get("document"):
            raise AssertionError(
                "Web impact canonical request document changed"
            )
        _receipt_payload, transport_receipt = _physical_json(
            challenge_root,
            receipt.extra["transport_receipt_path"],
            expected_sha256=receipt.extra.get(
                "transport_receipt_sha256"
            ),
        )
        receipt_transport = transport_receipt.get("transport")
        if (
            transport_receipt.get("receipt_id") != receipt_id
            or transport_receipt.get("run_id") != run_id
            or transport_receipt.get("request_sha256")
            != plan_request.get("request_sha256")
            or transport_receipt.get(
                "transport_execution_contract_sha256"
            )
            != plan_request.get("transport_contract", {}).get(
                "transport_execution_contract_sha256"
            )
            or receipt_transport
            != {
                "clean_workspace": True,
                "exit_code": 0,
                "fresh_identity_state": True,
                "network_target_authorized": True,
                "orchestration_status": "completed",
                "timed_out": False,
            }
        ):
            raise AssertionError(
                "Web impact physical transport receipt changed"
            )
        _result_payload, result = _physical_json(
            challenge_root,
            run.result_path,
        )
        expected_capture_ids = [
            *(
                artifact_id
                for pair in zip(
                    replay["request_artifact_ids"],
                    replay["response_artifact_ids"],
                    strict=True,
                )
                for artifact_id in pair
            ),
            replay["trace_artifact_id"],
        ]
        if (
            set(result)
            != {
                "capture_artifact_ids",
                "category",
                "challenge_id",
                "contest_id",
                "observation_commitment_sha256",
                "protocol",
                "receipt_id",
                "receipt_sha256",
                "run_id",
                "schema_version",
            }
            or result.get("run_id") != run_id
            or result.get("protocol") != attempt.get("protocol")
            or result.get("schema_version") != 1
            or result.get("contest_id") != identity.contest_id
            or result.get("category") != identity.category
            or result.get("challenge_id") != identity.challenge_id
            or result.get("receipt_id") != receipt_id
            or result.get("receipt_sha256")
            != receipt.extra.get("transport_receipt_sha256")
            or result.get("observation_commitment_sha256")
            != transport_receipt.get(
                "observation_commitment_sha256"
            )
            or result.get("capture_artifact_ids")
            != expected_capture_ids
        ):
            raise AssertionError(
                "Web impact physical result sidecar changed"
            )
        _validation_payload, validation = _physical_json(
            challenge_root,
            run.validation_path,
        )
        if (
            set(validation)
            != {
                "ok",
                "protocol",
                "request_sha256",
                "run_id",
                "transport_execution_contract_sha256",
                "validated_at",
            }
            or validation.get("ok") is not True
            or validation.get("run_id") != run_id
            or validation.get("protocol") != attempt.get("protocol")
            or validation.get("request_sha256")
            != plan_request.get("request_sha256")
            or validation.get(
                "transport_execution_contract_sha256"
            )
            != plan_request.get("transport_contract", {}).get(
                "transport_execution_contract_sha256"
            )
        ):
            raise AssertionError(
                "Web impact physical validation sidecar changed"
            )
    return state, {
        "physical_artifacts": len(expected_artifact_ids),
        "physical_run_sidecars": len(replays) * 3,
        "physical_transport_receipts": len(replays),
    }


def _operator_and_driver(
    *,
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    vulnerable: Any,
    control: Any,
    image_digest: str,
) -> None:
    state = engine.store.load(identity)
    workspace = engine._workspace(state)
    steps: list[WebImpactDriverStep] = []
    for ordinal, (role, channel, route) in enumerate(
        ROUTES,
        start=1,
    ):
        locator = f"route-{ordinal:02d}.txt"
        payload = (route + "\n").encode("ascii")
        (workspace / locator).write_bytes(payload)
        steps.append(
            WebImpactDriverStep(
                ordinal=ordinal,
                channel=channel,
                role=role,
                method="GET",
                route=WebImpactDriverInput(
                    locator=locator,
                    sha256=_sha256(payload),
                    size_bytes=len(payload),
                ),
                body=None,
                follow=False,
                insecure=False,
                timeout_seconds=30,
            )
        )
    selected = tuple(steps)
    vulnerable_approved = {
        "binding_sha256": web_impact_target_binding_sha256(
            vulnerable
        ),
        "generation": vulnerable.generation,
        "kind": WEB_IMPACT_ALLOWLISTED_TARGET_KIND,
    }
    control_approved = {
        "binding_sha256": web_impact_target_binding_sha256(control),
        "generation": control.generation,
        "kind": WEB_IMPACT_ALLOWLISTED_TARGET_KIND,
    }
    source_pointer = _sha256(b"release-smoke:session-role")
    sink_pointer = _sha256(b"release-smoke:response-body")
    trace_contract = web_impact_trace_contract_sha256(
        source_kind="session_role",
        source_pointer_sha256=source_pointer,
        sink_kind="response_body",
        sink_pointer_sha256=sink_pointer,
        runtime_step_ordinal=len(selected),
    )
    operator_payload = _canonical_json(
        {
            "authorized_target": vulnerable_approved,
            "differential": {
                "expected_response_sha256": _sha256(CONTROL_BODY),
                "expected_response_size_bytes": len(CONTROL_BODY),
                "expected_status": 403,
                "target": control_approved,
            },
            "identities": [
                {
                    "principal_binding_sha256": _sha256(
                        f"release-smoke:{role}".encode("ascii")
                    ),
                    "role": role,
                }
                for role in WEB_IDENTITY_ROLES
            ],
            "oracle": {
                "expected_response_sha256": _sha256(VULNERABLE_BODY),
                "expected_response_size_bytes": len(VULNERABLE_BODY),
                "expected_status": 200,
                "impact_kind": "authorization_bypass",
                "sink_step_ordinal": len(selected),
            },
            "protocol": WEB_IMPACT_OPERATOR_SPEC_PROTOCOL,
            "runtime_image_digest": image_digest,
            "schema_version": 1,
            "source_manifest_sha256": state.metadata[
                "source_manifest_sha256"
            ],
            "source_sink": {
                "runtime_step_ordinal": len(selected),
                "sink_kind": "response_body",
                "sink_pointer_sha256": sink_pointer,
                "source_kind": "session_role",
                "source_pointer_sha256": source_pointer,
                "trace_contract_sha256": trace_contract,
            },
            "timeline": [
                {
                    "channel": step.channel,
                    "expected_status": 200,
                    "method": step.method,
                    "ordinal": step.ordinal,
                    "request_shape_sha256": (
                        step.request_shape_sha256
                    ),
                    "role": step.role,
                    "route_binding_sha256": (
                        step.route_binding_sha256
                    ),
                }
                for step in selected
            ],
        }
    )
    driver = WebImpactDriverManifest(
        operator_spec_sha256=_sha256(operator_payload),
        vulnerable_target_id=vulnerable.id,
        control_target_id=control.id,
        steps=selected,
    )
    (workspace / "web-impact-spec.json").write_bytes(
        operator_payload
    )
    (workspace / "web-impact-driver.json").write_bytes(
        driver.canonical_bytes
    )


def _prove(
    root: Path,
    *,
    image_digest: str,
    network: str,
    vulnerable_host: str,
    control_host: str,
) -> dict[str, object]:
    engine = _engine(root, image_digest)
    identity = ChallengeIdentity(
        "release-smoke",
        "web",
        "impact-hotpath",
    )
    incoming = engine.challenge_input(identity)
    incoming.mkdir(parents=True)
    (incoming / "app.py").write_text(
        "# immutable release-smoke Web challenge\n",
        encoding="utf-8",
    )
    engine.add_challenge(
        identity,
        prompt="operator-explicit local release smoke",
        state_schema_version=STATE_SCHEMA_VERSION,
    )
    state = engine.add_network_target(
        identity,
        f"http://{vulnerable_host}:{TARGET_PORT}",
        docker_network=network,
        enforcement="proxy",
        purpose="release-smoke vulnerable target",
    )
    vulnerable = state.targets[-1]
    state = engine.add_network_target(
        identity,
        f"http://{control_host}:{TARGET_PORT}",
        docker_network=network,
        enforcement="proxy",
        purpose="release-smoke patched control",
    )
    control = state.targets[-1]
    state = engine.select_network_target(identity, vulnerable.id)
    initial_status = state.status
    _operator_and_driver(
        engine=engine,
        identity=identity,
        vulnerable=vulnerable,
        control=control,
        image_digest=image_digest,
    )

    _final, evaluation = engine.prove_web_impact(
        identity,
        operator_spec_locator="web-impact-spec.json",
        driver_locator="web-impact-driver.json",
        timeout_seconds=600,
    )
    canonical, physical = _revalidate_physical_web_impact(
        engine,
        identity,
        evaluation_sha256=evaluation.sha256,
        expected_replay_count=6,
    )
    validate_web_impact_state_graph(canonical)
    attempts = canonical.extra.get("web_impact_preissues")
    attempt = (
        next(reversed(attempts.values()))
        if type(attempts) is dict and attempts
        else None
    )
    state_path = engine.store.challenge_paths(identity).state
    state_bytes = state_path.read_bytes()
    forbidden = (*COOKIE_VALUES, VULNERABLE_BODY, CONTROL_BODY)
    if any(value in state_bytes for value in forbidden):
        raise AssertionError("raw Web secret/body entered canonical state")
    evaluation_document = evaluation.to_dict()
    evaluation_authorities = evaluation_document["authorities"]
    if (
        evaluation.confirmed is not True
        or evaluation.runtime_request_response_differential_confirmed
        is not True
        or evaluation.source_sink_observed is not False
        or evaluation_document[
            "runtime_request_response_differential_confirmed"
        ]
        is not True
        or evaluation_document["source_sink_observed"] is not False
        or evaluation_authorities[
            "runtime_request_response_differential_confirmed"
        ]
        is not True
        or evaluation_authorities["source_sink_observed"] is not False
        or len(evaluation.records) != 6
        or canonical.status is not initial_status
        or canonical.candidates
        or canonical.submissions
        or len(canonical.facts) != 1
        or canonical.facts[0].provenance is not Provenance.EXECUTED
        or len(canonical.progress_markers) != 1
        or type(attempt) is not dict
        or attempt.get("status") != "completed"
        or len(attempt.get("replays", ())) != 6
        or len(attempt.get("canonical_requests", ())) != 6
    ):
        raise AssertionError(
            "ChallengeEngine Web Docker hot path did not confirm exact 3+3"
        )
    return {
        "automatic_submissions": len(canonical.submissions),
        "canonical_requests_preissued": len(
            attempt["canonical_requests"]
        ),
        "executed_facts": len(canonical.facts),
        "network_enforcement": "proxy",
        "physical_artifacts_revalidated": physical[
            "physical_artifacts"
        ],
        "physical_run_sidecars_revalidated": physical[
            "physical_run_sidecars"
        ],
        "physical_transport_receipts_revalidated": physical[
            "physical_transport_receipts"
        ],
        "progress_markers": len(canonical.progress_markers),
        "replays": len(evaluation.records),
        "runtime_request_response_differential_confirmed": (
            evaluation.runtime_request_response_differential_confirmed
        ),
        "source_sink_observed": evaluation.source_sink_observed,
        "state_revision": canonical.revision,
        "verdict": evaluation.verdict.value,
    }


def _cleanup(
    *,
    containers: tuple[str, ...],
    network: str,
) -> None:
    failures: list[str] = []
    for name in containers:
        result = _docker(
            ("container", "rm", "--force", name),
            timeout=30,
            check=False,
        )
        if result.returncode not in {0, 1}:
            failures.append(
                f"container {name}: {result.stderr.strip()[:512]}"
            )
    result = _docker(
        ("network", "rm", network),
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        failures.append(
            f"network {network}: {result.stderr.strip()[:512]}"
        )
    if failures:
        raise RuntimeError(
            "release-smoke cleanup failed: " + "; ".join(failures)
        )


def main() -> int:
    image_digest = validate_image_digest(_parse_args().image_digest)
    readiness = inspect_pinned_capabilities(image_digest)
    if readiness.get("ok") is not True:
        raise AssertionError(
            "pinned image readiness failed: "
            + json.dumps(readiness, sort_keys=True)
        )

    suffix = f"{os.getpid()}-{secrets.token_hex(4)}"
    network = f"ctfos-web-smoke-{suffix}"
    vulnerable_name = f"ctfos-web-vulnerable-{suffix}"
    control_name = f"ctfos-web-control-{suffix}"
    vulnerable_host = f"vulnerable-{suffix}"
    control_host = f"control-{suffix}"
    containers = (vulnerable_name, control_name)
    primary_error: BaseException | None = None
    result: dict[str, object] | None = None
    with tempfile.TemporaryDirectory(
        prefix="ctfos-web-impact-docker-"
    ) as temporary:
        root = Path(temporary)
        server = root / "web-target.py"
        server.write_text(TARGET_SERVER_SOURCE, encoding="utf-8")
        server.chmod(stat.S_IRUSR)
        try:
            _docker(
                (
                    "network",
                    "create",
                    "--driver",
                    "bridge",
                    "--internal",
                    "--label",
                    "ctfos.release_smoke=web-impact",
                    network,
                )
            )
            network_details = json.loads(
                _docker(("network", "inspect", network)).stdout
            )
            if (
                type(network_details) is not list
                or len(network_details) != 1
                or network_details[0].get("Internal") is not True
            ):
                raise AssertionError(
                    "release-smoke Docker network is not internal"
                )
            _start_target(
                image_digest=image_digest,
                network=network,
                name=vulnerable_name,
                alias=vulnerable_host,
                mode="vulnerable",
                server_path=server,
            )
            _start_target(
                image_digest=image_digest,
                network=network,
                name=control_name,
                alias=control_host,
                mode="control",
                server_path=server,
            )
            _wait_healthy(vulnerable_name)
            _wait_healthy(control_name)
            engine_result = _prove(
                root / "engine",
                image_digest=image_digest,
                network=network,
                vulnerable_host=vulnerable_host,
                control_host=control_host,
            )
            vulnerable_audit = _target_audit(
                vulnerable_name,
                "vulnerable",
            )
            control_audit = _target_audit(
                control_name,
                "control",
            )
            result = {
                "control_target": control_audit,
                "engine": engine_result,
                "image_digest": image_digest,
                "network": {
                    "external_internet": False,
                    "internal": True,
                    "name": network,
                },
                "ok": True,
                "vulnerable_target": vulnerable_audit,
            }
        except BaseException as error:
            primary_error = error
        try:
            _cleanup(containers=containers, network=network)
        except BaseException as cleanup_error:
            if primary_error is not None:
                primary_error.add_note(str(cleanup_error))
            else:
                raise
        if primary_error is not None:
            raise primary_error
    assert result is not None
    print(
        json.dumps(
            result,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
