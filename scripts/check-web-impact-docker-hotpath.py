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
from ctf_os.models import ChallengeIdentity, Provenance
from ctf_os.schema import STATE_SCHEMA_VERSION


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


def _target_audit(name: str, mode: str) -> dict[str, object]:
    lines = _docker(("logs", name), timeout=30).stdout.splitlines()
    events: list[dict[str, Any]] = []
    for line in lines:
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise AssertionError(
                f"{mode} target emitted a non-JSON audit line"
            ) from error
        if type(value) is not dict:
            raise AssertionError(f"{mode} target audit is not an object")
        if value.get("path") != "/health":
            events.append(value)
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

    final, evaluation = engine.prove_web_impact(
        identity,
        operator_spec_locator="web-impact-spec.json",
        driver_locator="web-impact-driver.json",
        timeout_seconds=600,
    )
    validate_web_impact_state_graph(final)
    attempts = final.extra.get("web_impact_preissues")
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
        or final.status is not initial_status
        or final.candidates
        or final.submissions
        or len(final.facts) != 1
        or final.facts[0].provenance is not Provenance.EXECUTED
        or len(final.progress_markers) != 1
        or type(attempt) is not dict
        or attempt.get("status") != "completed"
        or len(attempt.get("replays", ())) != 6
        or len(attempt.get("canonical_requests", ())) != 6
    ):
        raise AssertionError(
            "ChallengeEngine Web Docker hot path did not confirm exact 3+3"
        )
    return {
        "automatic_submissions": len(final.submissions),
        "canonical_requests_preissued": len(
            attempt["canonical_requests"]
        ),
        "executed_facts": len(final.facts),
        "network_enforcement": "proxy",
        "progress_markers": len(final.progress_markers),
        "replays": len(evaluation.records),
        "runtime_request_response_differential_confirmed": (
            evaluation.runtime_request_response_differential_confirmed
        ),
        "source_sink_observed": evaluation.source_sink_observed,
        "state_revision": final.revision,
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
