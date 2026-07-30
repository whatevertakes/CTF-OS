from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from ctf_os import cli
from ctf_os.config import load_config
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.web_active_probe import (
    WEB_ACTIVE_PROBE_DRIVER_PROTOCOL,
    WEB_ACTIVE_PROBE_HELPER_PROTOCOL,
    WEB_ACTIVE_PROBE_OPERATOR_PROTOCOL,
)
from ctf_os.engine.web_active_probe_state import (
    WebActiveProbeStateContractError,
    validate_web_active_probe_state_graph,
)
from ctf_os.engine.web_impact_driver import (
    WebImpactDriverInput,
    WebImpactDriverStep,
    web_impact_target_binding_sha256,
)
from ctf_os.models import ChallengeIdentity, Provenance
from ctf_os.sandbox import ArtifactRef, SandboxResult
from ctf_os.schema import STATE_SCHEMA_VERSION


IMAGE_DIGEST = "sha256:" + ("6" * 64)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _digest(label: str) -> str:
    return _sha256(label.encode("ascii"))


def _json(value: object) -> bytes:
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


class _ActiveSandbox:
    scope_fingerprint = "a" * 64

    def __init__(self, owner: "_Coordinator", work: Path, policy) -> None:
        self.owner = owner
        self.work = work
        self.policy = policy

    def initialize_workspace(self, *, deadline_monotonic_seconds=None):
        del deadline_monotonic_seconds
        self.work.mkdir(parents=True, exist_ok=True)

    def register_artifact(self, locator, *, maximum_bytes=1 << 34):
        payload = (self.work / locator).read_bytes()
        if len(payload) > maximum_bytes:
            raise ValueError("test artifact exceeds bound")
        return ArtifactRef(
            locator=locator,
            sha256=_sha256(payload),
            size_bytes=len(payload),
            scope_fingerprint=self.scope_fingerprint,
        )

    def run(self, spec):
        self.owner.total_runs += 1
        self.owner.specs.append(spec)
        self.owner.policies.append(self.policy)
        state = self.owner.engine.store.load(self.owner.identity)
        attempt = next(
            reversed(state.extra["web_active_probe_preissues"].values())
        )
        if attempt["status"] != "running":
            raise AssertionError("active replay lacks running preissue")
        if len(attempt["issues"]) != 6:
            raise AssertionError("full 3+3 replay matrix was not preissued")
        for issue in attempt["issues"]:
            request = self.owner.engine.store.run_paths(
                self.owner.identity,
                issue["run_id"],
            ).request
            if not request.is_file():
                raise AssertionError("run request was not preissued")
        if spec.argv[0] != "/opt/ctf-templates/web/active_probe.py":
            raise AssertionError("unexpected helper")
        target_kind = (
            "vulnerable"
            if self.owner.total_runs <= 3
            else "control"
        )
        bodies = (
            (b"won", b"lost")
            if target_kind == "vulnerable"
            else (b"control", b"control")
        )
        responses = []
        for index, body in enumerate(bodies, start=1):
            response = {
                "artifact": f"response-{index:04d}.bin",
                "attempt": 1,
                "body_sha256": _sha256(body),
                "body_size_bytes": len(body),
                "duration_ns": 1000,
                "index": index,
                "ordinal": index,
                "status": 200 if body == b"won" else 409,
                "truncated": False,
            }
            responses.append(response)
        batch_sha256 = _sha256(_json(responses))
        for response in responses:
            response["batch_sha256"] = batch_sha256
        output = self.work / "web-active"
        output.mkdir(parents=True, exist_ok=True)
        for index, body in enumerate(bodies, start=1):
            (output / f"response-{index:04d}.bin").write_bytes(body)
        report = {
            "artifact_names": [
                "response-0001.bin",
                "response-0002.bin",
            ],
            "attempts": 1,
            "concurrency": 2,
            "cookie_transition_sha256": _digest(
                f"cookie-transition:{self.owner.total_runs}"
            ),
            "elapsed_ns": 10000,
            "mode": "race",
            "protocol": WEB_ACTIVE_PROBE_HELPER_PROTOCOL,
            "request_count": 2,
            "responses": responses,
            "schema_version": 1,
            "session": "attacker",
            "timeline_ordinal": 1,
        }
        (output / "report.json").write_bytes(_json(report))
        (output / "timeline.json").write_bytes(
            _json(
                {
                    "events": [],
                    "omitted_events": 0,
                    "schema_version": 1,
                }
            )
        )
        return SandboxResult(
            run_id=f"active-{self.owner.total_runs:08d}",
            status="completed",
            exit_code=0,
            timed_out=False,
            duration_ms=1,
            stdout_summary="",
            stderr_summary="",
            stdout_bytes=0,
            stderr_bytes=0,
            stdout_path="/work/stdout.log",
            stderr_path="/work/stderr.log",
            stdout_stored_bytes=0,
            stderr_stored_bytes=0,
            stdout_limit_bytes=1,
            stderr_limit_bytes=1,
            stdout_truncated=False,
            stderr_truncated=False,
            stdout_truncation_known=True,
            stderr_truncation_known=True,
            stdout_capture_complete=True,
            stderr_capture_complete=True,
            orchestration_error=None,
        )


class _Coordinator:
    def __init__(self, identity: ChallengeIdentity) -> None:
        self.identity = identity
        self.engine: ChallengeEngine
        self.total_runs = 0
        self.specs = []
        self.policies = []

    def factory(self, _state, work, policy):
        return _ActiveSandbox(self, work, policy)


class WebActiveProbeHotPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.identity = ChallengeIdentity(
            "Web Active CTF",
            "web",
            "race",
        )
        self.coordinator = _Coordinator(self.identity)
        base = load_config(self.root)
        config = replace(
            base,
            runtime=replace(
                base.runtime,
                image_digest=IMAGE_DIGEST,
            ),
        )
        self.engine = ChallengeEngine(
            self.root,
            config=config,
            sandbox_factory=self.coordinator.factory,
        )
        self.coordinator.engine = self.engine
        incoming = self.engine.challenge_input(self.identity)
        incoming.mkdir(parents=True)
        (incoming / "app.py").write_bytes(b"print('race')\n")
        state = self.engine.add_challenge(
            self.identity,
            prompt="prove the race",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        state = self.engine.add_network_target(
            self.identity,
            "https://vulnerable.test",
            docker_network="ctf-active-net",
            enforcement="proxy",
        )
        vulnerable = state.targets[-1]
        state = self.engine.add_network_target(
            self.identity,
            "https://control.test",
            docker_network="ctf-active-net",
            enforcement="proxy",
        )
        control = state.targets[-1]
        workspace = self.engine._workspace(state)
        route_payload = b"/claim\n"
        body_payload = b'{"claim":true}'
        (workspace / "route.txt").write_bytes(route_payload)
        (workspace / "body.json").write_bytes(body_payload)
        route = WebImpactDriverInput(
            locator="route.txt",
            sha256=_sha256(route_payload),
            size_bytes=len(route_payload),
        )
        body = WebImpactDriverInput(
            locator="body.json",
            sha256=_sha256(body_payload),
            size_bytes=len(body_payload),
        )
        probe = WebImpactDriverStep(
            ordinal=1,
            channel="http",
            role="attacker",
            method="POST",
            route=route,
            body=body,
            follow=False,
            insecure=False,
            timeout_seconds=10,
        )
        request = {
            "body_sha256": body.sha256,
            "body_size_bytes": body.size_bytes,
            "method": probe.method,
            "request_shape_sha256": probe.request_shape_sha256,
            "route_sha256": route.sha256,
            "route_size_bytes": route.size_bytes,
        }
        state = self.engine.store.load(self.identity)
        spec = {
            "control_target": {
                "binding_sha256": (
                    web_impact_target_binding_sha256(control)
                ),
                "generation": control.generation,
                "kind": "allowlisted_http_origin_v1",
            },
            "identity": {
                "principal_binding_sha256": _digest("attacker"),
                "role": "attacker",
            },
            "mode": "race",
            "oracle": {
                "control": _signature(b"control", 409),
                "impact": _signature(b"won", 200),
                "minimum_impact_count": 1,
                "vulnerable_nonimpact": _signature(b"lost", 409),
            },
            "probe": request,
            "protocol": WEB_ACTIVE_PROBE_OPERATOR_PROTOCOL,
            "runtime_image_digest": IMAGE_DIGEST,
            "schema_version": 1,
            "setup": [],
            "source_manifest_sha256": state.metadata[
                "source_manifest_sha256"
            ],
            "transport": {"attempts": 1, "concurrency": 2},
            "vulnerable_target": {
                "binding_sha256": (
                    web_impact_target_binding_sha256(vulnerable)
                ),
                "generation": vulnerable.generation,
                "kind": "allowlisted_http_origin_v1",
            },
        }
        spec_payload = _json(spec)
        (workspace / "active-spec.json").write_bytes(spec_payload)
        step = probe.to_dict()
        step.pop("channel")
        step.pop("role")
        driver = {
            "control_target_id": control.id,
            "operator_spec_sha256": _sha256(spec_payload),
            "probe": step,
            "protocol": WEB_ACTIVE_PROBE_DRIVER_PROTOCOL,
            "schema_version": 1,
            "setup": [],
            "vulnerable_target_id": vulnerable.id,
        }
        (workspace / "active-driver.json").write_bytes(_json(driver))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _prove(self):
        return self.engine.prove_web_active_probe(
            self.identity,
            operator_spec_locator="active-spec.json",
            driver_locator="active-driver.json",
            timeout_seconds=120,
        )

    def test_success_preissues_six_and_query_revalidates_bytes(self):
        before = self.engine.store.load(self.identity)
        state, evaluation = self._prove()
        self.assertTrue(evaluation["confirmed"])
        self.assertEqual(self.coordinator.total_runs, 6)
        self.assertEqual(
            len(state.experiments),
            len(before.experiments) + 6,
        )
        self.assertEqual(len(state.runs), len(before.runs) + 6)
        self.assertEqual(
            len(state.receipts),
            len(before.receipts) + 6,
        )
        self.assertEqual(len(state.facts), len(before.facts) + 1)
        self.assertIs(state.facts[-1].provenance, Provenance.EXECUTED)
        self.assertEqual(state.candidates, before.candidates)
        self.assertEqual(state.submissions, before.submissions)
        self.assertIs(state.status, before.status)
        self.assertTrue(
            all(
                policy.enforcement == "proxy"
                and len(policy.allow_targets) == 1
                for policy in self.coordinator.policies
            )
        )
        validate_web_active_probe_state_graph(state)
        query = self.engine.query_web_active_probe(self.identity)
        self.assertTrue(query["ok"])
        self.assertTrue(query["confirmed"])
        self.assertEqual(query["replay_count"], 6)
        self.assertFalse(query["raw_output_returned"])

    def test_rehashed_semantic_tamper_and_physical_tamper_reject(self):
        state, _evaluation = self._prove()
        hostile = copy.deepcopy(state)
        wrapper = next(
            iter(hostile.extra["web_active_probe_graphs"].values())
        )
        wrapper["graph"]["records"][0]["passed"] = False
        wrapper["graph_sha256"] = _sha256(
            _json(wrapper["graph"])
        )
        with self.assertRaises(WebActiveProbeStateContractError):
            validate_web_active_probe_state_graph(hostile)

        output = next(
            item
            for item in state.artifacts
            if item.extra.get("kind") == "web_active_probe_output"
        )
        path = (
            self.engine.store.challenge_paths(self.identity).root
            / output.path
        )
        path.chmod(0o600)
        path.write_bytes(b"tampered")
        path.chmod(0o400)
        with self.assertRaises(Exception):
            self.engine.query_web_active_probe(self.identity)

    def test_cli_exposes_exact_active_probe_arguments(self):
        parsed = cli.build_parser().parse_args(
            [
                "web-prove-active",
                self.identity.contest_id,
                self.identity.category,
                self.identity.challenge_id,
                "--spec",
                "active-spec.json",
                "--driver",
                "active-driver.json",
                "--hypothesis",
                "H-web-race",
                "--timeout",
                "120",
            ]
        )
        self.assertEqual(parsed.command, "web-prove-active")
        self.assertEqual(parsed.hypothesis, ["H-web-race"])
        self.assertEqual(parsed.timeout, 120)


if __name__ == "__main__":
    unittest.main()
