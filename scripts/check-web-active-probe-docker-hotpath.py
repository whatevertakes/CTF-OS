#!/usr/bin/env python3
"""Prove Web race and OOB 3+3 gates through the pinned Docker image.

The smoke creates two local targets on one ephemeral Docker ``--internal``
network, then calls only the public ChallengeEngine active-probe API.  It
performs no model call, external request, candidate creation, submission, or
automatic challenge selection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from ctf_os.capabilities import inspect_pinned_capabilities
from ctf_os.config import EngineConfig, ResourceConfig, RuntimeConfig
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.web_active_probe import (
    WEB_ACTIVE_PROBE_DRIVER_PROTOCOL,
    WEB_ACTIVE_PROBE_OPERATOR_PROTOCOL,
)
from ctf_os.engine.web_active_probe_state import (
    validate_web_active_probe_state_graph,
)
from ctf_os.engine.web_impact_driver import (
    WebImpactDriverInput,
    WebImpactDriverStep,
    web_impact_target_binding_sha256,
)
from ctf_os.images import validate_image_digest
from ctf_os.models import ChallengeIdentity, Provenance
from ctf_os.schema import STATE_SCHEMA_VERSION


TARGET_PORT = 18081
RACE_IMPACT = b"race-impact-a7183c"
RACE_NONIMPACT = b"race-nonimpact-c42e91"
RACE_CONTROL = b"race-control-f59d20"
OOB_CALLBACK = b"oob-callback-b7318e"
OOB_VULNERABLE_TRIGGER = b"oob-trigger-vulnerable-9d7c12"
OOB_CONTROL_TRIGGER = b"oob-trigger-control-3f8a45"
CALLBACK_PLACEHOLDER = b"{{CTF_OOB_URL}}"

TARGET_SERVER_SOURCE = r"""
from __future__ import annotations

import json
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MODE = sys.argv[1]
PORT = int(sys.argv[2])
LOCK = threading.Lock()
RACE_COUNTER = 0
ACTIVE_RACE = 0
MAX_ACTIVE_RACE = 0


def emit(value):
    print(json.dumps(value, separators=(",", ":"), sort_keys=True), flush=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        return

    def _reply(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._reply(200, b"healthy")
            return
        self._reply(404, b"not-found")

    def do_POST(self):
        global ACTIVE_RACE, MAX_ACTIVE_RACE, RACE_COUNTER
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if self.path == "/race":
            with LOCK:
                ACTIVE_RACE += 1
                MAX_ACTIVE_RACE = max(MAX_ACTIVE_RACE, ACTIVE_RACE)
                RACE_COUNTER += 1
                ordinal = RACE_COUNTER
                active = ACTIVE_RACE
            time.sleep(0.15)
            if MODE == "vulnerable":
                status = 200 if ordinal % 2 else 409
                response = (
                    b"race-impact-a7183c"
                    if status == 200
                    else b"race-nonimpact-c42e91"
                )
            else:
                status = 409
                response = b"race-control-f59d20"
            self._reply(status, response)
            with LOCK:
                ACTIVE_RACE -= 1
                maximum = MAX_ACTIVE_RACE
            emit(
                {
                    "active_at_entry": active,
                    "kind": "race",
                    "max_active": maximum,
                    "mode": MODE,
                    "status": status,
                }
            )
            return
        if self.path == "/oob":
            try:
                request = json.loads(body)
                callback = request["callback"]
                if (
                    type(callback) is not str
                    or not callback.startswith("http://")
                ):
                    raise ValueError("callback")
            except Exception:
                self._reply(400, b"bad-request")
                return
            called_back = False
            if MODE == "vulnerable":
                callback_request = urllib.request.Request(
                    callback,
                    data=b"oob-callback-b7318e",
                    method="POST",
                )
                with urllib.request.urlopen(
                    callback_request,
                    timeout=5,
                ) as response:
                    if response.status != 204:
                        raise RuntimeError("callback rejected")
                called_back = True
                self._reply(202, b"oob-trigger-vulnerable-9d7c12")
            else:
                self._reply(403, b"oob-trigger-control-3f8a45")
            emit(
                {
                    "called_back": called_back,
                    "kind": "oob",
                    "mode": MODE,
                    "status": 202 if called_back else 403,
                }
            )
            return
        self._reply(404, b"not-found")


server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
server.daemon_threads = True
server.serve_forever()
""".lstrip()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--image-digest",
        required=True,
        help="exact local sha256:<64 lowercase hex> image ID",
    )
    return parser.parse_args()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(value: object) -> bytes:
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


def _signature(payload: bytes, status: int) -> dict[str, object]:
    return {
        "body_sha256": _sha256(payload),
        "body_size_bytes": len(payload),
        "status": status,
    }


def _docker(
    argv: tuple[str, ...],
    *,
    check: bool = True,
    timeout: int = 180,
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
        raise RuntimeError(
            f"docker {' '.join(argv[:4])} failed: "
            f"{result.stderr.strip()[:4096]}"
        )
    return result


def _start_target(
    *,
    image_digest: str,
    network: str,
    name: str,
    alias: str,
    mode: str,
    source: Path,
) -> None:
    _docker(
        (
            "run",
            "--detach",
            "--name",
            name,
            "--label",
            "ctfos.release_smoke=web-active",
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
            "96",
            "--memory",
            "256m",
            "--cpus",
            "1",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=16m",
            "--mount",
            (
                f"type=bind,src={source},"
                "dst=/opt/ctfos-release/active-target.py,readonly"
            ),
            "--entrypoint",
            "/usr/bin/python3",
            image_digest,
            "/opt/ctfos-release/active-target.py",
            mode,
            str(TARGET_PORT),
        )
    )


def _wait_healthy(name: str) -> None:
    command = (
        "import urllib.request;"
        f"r=urllib.request.urlopen('http://127.0.0.1:{TARGET_PORT}/health',"
        "timeout=2);"
        "assert r.status == 200 and r.read() == b'healthy'"
    )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        result = _docker(
            (
                "exec",
                name,
                "/usr/bin/python3",
                "-c",
                command,
            ),
            check=False,
            timeout=5,
        )
        if result.returncode == 0:
            return
        time.sleep(0.1)
    raise RuntimeError(f"target {name} did not become healthy")


def _engine(root: Path, image_digest: str) -> ChallengeEngine:
    return ChallengeEngine(
        root,
        config=EngineConfig(
            workspace_root=root,
            resources=ResourceConfig(
                remote_command_min_interval_s=0.0,
            ),
            runtime=RuntimeConfig(
                image="ctf-os:web-active-smoke",
                image_digest=image_digest,
                network_default="none",
                command_timeout_s=90,
            ),
        ),
    )


def _target_binding(target: Any) -> dict[str, object]:
    return {
        "binding_sha256": web_impact_target_binding_sha256(target),
        "generation": target.generation,
        "kind": "allowlisted_http_origin_v1",
    }


def _write_documents(
    *,
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    vulnerable: Any,
    control: Any,
    image_digest: str,
    mode: str,
) -> None:
    state = engine.store.load(identity)
    workspace = engine._workspace(state)
    route_payload = f"/{mode}\n".encode("ascii")
    body_payload = (
        b'{"claim":true}'
        if mode == "race"
        else b'{"callback":"{{CTF_OOB_URL}}"}'
    )
    route_locator = f"{mode}-route.txt"
    body_locator = f"{mode}-body.json"
    (workspace / route_locator).write_bytes(route_payload)
    (workspace / body_locator).write_bytes(body_payload)
    route = WebImpactDriverInput(
        locator=route_locator,
        sha256=_sha256(route_payload),
        size_bytes=len(route_payload),
    )
    body = WebImpactDriverInput(
        locator=body_locator,
        sha256=_sha256(body_payload),
        size_bytes=len(body_payload),
    )
    step = WebImpactDriverStep(
        ordinal=1,
        channel="http",
        role="attacker",
        method="POST",
        route=route,
        body=body,
        follow=False,
        insecure=False,
        timeout_seconds=30,
    )
    request = {
        "body_sha256": body.sha256,
        "body_size_bytes": body.size_bytes,
        "method": step.method,
        "request_shape_sha256": step.request_shape_sha256,
        "route_sha256": route.sha256,
        "route_size_bytes": route.size_bytes,
    }
    if mode == "race":
        transport: dict[str, object] = {
            "attempts": 1,
            "concurrency": 2,
        }
        oracle: dict[str, object] = {
            "control": _signature(RACE_CONTROL, 409),
            "impact": _signature(RACE_IMPACT, 200),
            "minimum_impact_count": 1,
            "vulnerable_nonimpact": _signature(
                RACE_NONIMPACT,
                409,
            ),
        }
    else:
        transport = {"callback_timeout_seconds": 10}
        oracle = {
            "callback": {
                "body_sha256": _sha256(OOB_CALLBACK),
                "body_size_bytes": len(OOB_CALLBACK),
                "method": "POST",
            },
            "control_trigger": _signature(
                OOB_CONTROL_TRIGGER,
                403,
            ),
            "vulnerable_trigger": _signature(
                OOB_VULNERABLE_TRIGGER,
                202,
            ),
        }
    spec_payload = _canonical(
        {
            "control_target": _target_binding(control),
            "identity": {
                "principal_binding_sha256": _sha256(
                    b"release-smoke-attacker"
                ),
                "role": "attacker",
            },
            "mode": mode,
            "oracle": oracle,
            "probe": request,
            "protocol": WEB_ACTIVE_PROBE_OPERATOR_PROTOCOL,
            "runtime_image_digest": image_digest,
            "schema_version": 1,
            "setup": [],
            "source_manifest_sha256": state.metadata[
                "source_manifest_sha256"
            ],
            "transport": transport,
            "vulnerable_target": _target_binding(vulnerable),
        }
    )
    projected = step.to_dict()
    projected.pop("channel")
    projected.pop("role")
    driver_payload = _canonical(
        {
            "control_target_id": control.id,
            "operator_spec_sha256": _sha256(spec_payload),
            "probe": projected,
            "protocol": WEB_ACTIVE_PROBE_DRIVER_PROTOCOL,
            "schema_version": 1,
            "setup": [],
            "vulnerable_target_id": vulnerable.id,
        }
    )
    (workspace / f"{mode}-spec.json").write_bytes(spec_payload)
    (workspace / f"{mode}-driver.json").write_bytes(driver_payload)


def _prove_mode(
    root: Path,
    *,
    image_digest: str,
    network: str,
    mode: str,
) -> dict[str, object]:
    engine = _engine(root, image_digest)
    identity = ChallengeIdentity(
        "release-smoke",
        "web",
        f"active-{mode}",
    )
    incoming = engine.challenge_input(identity)
    incoming.mkdir(parents=True)
    (incoming / "app.py").write_text(
        "# immutable Web active-probe release smoke\n",
        encoding="utf-8",
    )
    engine.add_challenge(
        identity,
        prompt=f"operator-explicit {mode} release smoke",
        state_schema_version=STATE_SCHEMA_VERSION,
    )
    state = engine.add_network_target(
        identity,
        f"http://active-vulnerable:{TARGET_PORT}",
        docker_network=network,
        enforcement="proxy",
        purpose="release-smoke vulnerable target",
    )
    vulnerable = state.targets[-1]
    state = engine.add_network_target(
        identity,
        f"http://active-control:{TARGET_PORT}",
        docker_network=network,
        enforcement="proxy",
        purpose="release-smoke patched control",
    )
    control = state.targets[-1]
    _write_documents(
        engine=engine,
        identity=identity,
        vulnerable=vulnerable,
        control=control,
        image_digest=image_digest,
        mode=mode,
    )
    before = engine.store.load(identity)
    final, evaluation = engine.prove_web_active_probe(
        identity,
        operator_spec_locator=f"{mode}-spec.json",
        driver_locator=f"{mode}-driver.json",
        timeout_seconds=600,
    )
    validate_web_active_probe_state_graph(final)
    query = engine.validate_web_active_probe(identity)
    state_payload = engine.store.challenge_paths(
        identity
    ).state.read_bytes()
    forbidden = (
        RACE_IMPACT,
        RACE_NONIMPACT,
        RACE_CONTROL,
        OOB_CALLBACK,
        OOB_VULNERABLE_TRIGGER,
        OOB_CONTROL_TRIGGER,
        CALLBACK_PLACEHOLDER,
    )
    if (
        evaluation["confirmed"] is not True
        or query["confirmed"] is not True
        or query["replay_count"] != 6
        or len(final.experiments) != len(before.experiments) + 6
        or len(final.runs) != len(before.runs) + 6
        or len(final.receipts) != len(before.receipts) + 6
        or len(final.facts) != len(before.facts) + 1
        or final.facts[-1].provenance is not Provenance.EXECUTED
        or len(final.progress_markers)
        != len(before.progress_markers) + 1
        or final.candidates != before.candidates
        or final.submissions != before.submissions
        or final.status is not before.status
        or any(value in state_payload for value in forbidden)
    ):
        raise AssertionError(
            f"public {mode} active-probe proof did not pass exactly"
        )
    return {
        "attempt_id": query["attempt_id"],
        "candidate_count": len(final.candidates),
        "evaluation_sha256": evaluation["evaluation_sha256"],
        "executed_fact_count": len(final.facts) - len(before.facts),
        "graph_sha256": query["graph_sha256"],
        "mode": mode,
        "physical_artifact_count": query[
            "physical_artifact_count"
        ],
        "replay_count": query["replay_count"],
        "submission_count": len(final.submissions),
    }


def _audit_targets(
    vulnerable_name: str,
    control_name: str,
) -> dict[str, object]:
    values: dict[str, list[dict[str, object]]] = {}
    for mode, name in (
        ("vulnerable", vulnerable_name),
        ("control", control_name),
    ):
        events = []
        for line in _docker(("logs", name), timeout=30).stdout.splitlines():
            value = json.loads(line)
            if type(value) is dict:
                events.append(value)
        values[mode] = events
    vulnerable = values["vulnerable"]
    control = values["control"]
    race_vulnerable = [
        item for item in vulnerable if item.get("kind") == "race"
    ]
    race_control = [
        item for item in control if item.get("kind") == "race"
    ]
    oob_vulnerable = [
        item for item in vulnerable if item.get("kind") == "oob"
    ]
    oob_control = [
        item for item in control if item.get("kind") == "oob"
    ]
    if (
        len(race_vulnerable) != 6
        or len(race_control) != 6
        or max(
            int(item["max_active"]) for item in race_vulnerable
        )
        < 2
        or {item["status"] for item in race_vulnerable}
        != {200, 409}
        or {item["status"] for item in race_control} != {409}
        or len(oob_vulnerable) != 3
        or len(oob_control) != 3
        or any(
            item.get("called_back") is not True
            for item in oob_vulnerable
        )
        or any(
            item.get("called_back") is not False
            for item in oob_control
        )
    ):
        raise AssertionError(
            "target audit did not prove true race and OOB differential"
        )
    return {
        "control_oob_callbacks": 0,
        "control_race_requests": len(race_control),
        "maximum_parallel_race_requests": max(
            int(item["max_active"]) for item in race_vulnerable
        ),
        "vulnerable_oob_callbacks": len(oob_vulnerable),
        "vulnerable_race_requests": len(race_vulnerable),
    }


def _cleanup(containers: tuple[str, ...], network: str) -> None:
    for name in containers:
        _docker(
            ("container", "rm", "--force", name),
            check=False,
            timeout=30,
        )
    _docker(
        ("network", "rm", network),
        check=False,
        timeout=30,
    )


def main() -> int:
    args = _parse_args()
    image_digest = validate_image_digest(args.image_digest)
    readiness = inspect_pinned_capabilities(image_digest)
    active_tool = json.loads(
        _docker(
            (
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--entrypoint",
                "ctf-tools",
                image_digest,
                "--json",
                "--info",
                "ctf-web-probe",
            ),
            timeout=30,
        ).stdout
    )
    if readiness.get("ok") is not True or (
        type(active_tool) is not dict
        or active_tool.get("found") is not True
        or active_tool.get("tool", {}).get("available") is not True
    ):
        raise RuntimeError(
            "pinned image does not expose ctf-web-probe"
        )
    suffix = secrets.token_hex(6)
    network = f"ctfos-web-active-{suffix}"
    vulnerable_name = f"ctfos-active-vuln-{suffix}"
    control_name = f"ctfos-active-control-{suffix}"
    containers = (vulnerable_name, control_name)
    _docker(
        (
            "network",
            "create",
            "--internal",
            "--label",
            "ctfos.release_smoke=web-active",
            network,
        )
    )
    try:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-web-active-release-"
        ) as temporary:
            root = Path(temporary)
            target_source = root / "active-target.py"
            target_source.write_text(
                TARGET_SERVER_SOURCE,
                encoding="utf-8",
            )
            _start_target(
                image_digest=image_digest,
                network=network,
                name=vulnerable_name,
                alias="active-vulnerable",
                mode="vulnerable",
                source=target_source,
            )
            _start_target(
                image_digest=image_digest,
                network=network,
                name=control_name,
                alias="active-control",
                mode="control",
                source=target_source,
            )
            _wait_healthy(vulnerable_name)
            _wait_healthy(control_name)
            race = _prove_mode(
                root / "race-engine",
                image_digest=image_digest,
                network=network,
                mode="race",
            )
            oob = _prove_mode(
                root / "oob-engine",
                image_digest=image_digest,
                network=network,
                mode="oob",
            )
            audit = _audit_targets(
                vulnerable_name,
                control_name,
            )
            print(
                _canonical(
                    {
                        "automatic_submission_count": 0,
                        "external_network": False,
                        "image_digest": image_digest,
                        "oob": oob,
                        "protocol": (
                            "ctfos.web.active_probe.docker_release.v1"
                        ),
                        "race": race,
                        "schema_version": 1,
                        "target_audit": audit,
                    }
                ).decode("ascii"),
                end="",
            )
    finally:
        _cleanup(containers, network)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
