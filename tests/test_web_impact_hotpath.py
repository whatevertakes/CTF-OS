from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from ctf_os import cli
from ctf_os.config import load_config
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.web_impact import WEB_IDENTITY_ROLES
from ctf_os.engine.web_impact_driver import (
    WEB_IMPACT_DRIVER_PROTOCOL,
    WebImpactDriverError,
    WebImpactDriverInput,
    WebImpactDriverManifest,
    WebImpactDriverStep,
    parse_web_impact_driver_manifest,
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
from ctf_os.models import (
    ChallengeIdentity,
    Provenance,
)
from ctf_os.sandbox import (
    ArtifactRef,
    ChallengeScope,
    SandboxResult,
)
from ctf_os.sandbox.web_private import (
    private_web_identity_epoch_sha256,
    reset_private_web_identity_state,
    resolve_private_web_mounts,
)
from ctf_os.schema import STATE_SCHEMA_VERSION


IMAGE_DIGEST = "sha256:" + ("6" * 64)
FINAL_BODY = b"victim-impact-confirmed"


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _digest(label: str) -> str:
    return _sha256(label.encode("ascii"))


def _json_bytes(value: object) -> bytes:
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


class _WebSandbox:
    scope_fingerprint = "a" * 64

    def __init__(self, owner: "_Coordinator", work: Path, policy) -> None:
        self.owner = owner
        self.work = work
        self.policy = policy
        self.calls = 0

    def initialize_workspace(self, *, deadline_monotonic_seconds=None):
        del deadline_monotonic_seconds
        self.work.mkdir(parents=True, exist_ok=True)

    def register_artifact(self, locator, *, maximum_bytes=1 << 34):
        path = self.work / locator
        payload = path.read_bytes()
        if len(payload) > maximum_bytes:
            raise ValueError("test artifact exceeds bound")
        return ArtifactRef(
            locator=locator,
            sha256=_sha256(payload),
            size_bytes=len(payload),
            scope_fingerprint=self.scope_fingerprint,
        )

    def run(self, spec):
        self.calls += 1
        self.owner.total_runs += 1
        self.owner.policies.append(self.policy)
        self.owner.specs.append(spec)
        state = self.owner.engine.store.load(self.owner.identity)
        attempts = state.extra["web_impact_preissues"]
        attempt = next(reversed(attempts.values()))
        if attempt["status"] != "running":
            raise AssertionError("replay began without running preissue")
        if len(attempt["replays"]) != 3:
            raise AssertionError("all replay identities were not preissued")
        for replay in attempt["replays"]:
            request = (
                self.owner.engine.store.run_paths(
                    self.owner.identity,
                    replay["run_id"],
                ).request
            )
            if not request.is_file():
                raise AssertionError("canonical request was not preissued")
        if self.owner.interrupt_at == self.owner.total_runs:
            raise KeyboardInterrupt("synthetic Web interruption")
        if self.owner.mutate_source_at == self.owner.total_runs:
            self.owner.source.write_bytes(b"mutated-source")
        if self.owner.tamper_request_at == self.owner.total_runs:
            first = attempt["replays"][0]
            request = self.owner.engine.store.run_paths(
                self.owner.identity,
                first["run_id"],
            ).request
            request.chmod(0o600)
            request.write_bytes(b"{}\n")
            request.chmod(0o400)

        argv = spec.argv
        role = argv[argv.index("--session") + 1]
        channel = (
            "browser" if argv[0] == "ctf-browser" else "http"
        )
        method = (
            "GET"
            if channel == "browser"
            else argv[argv.index("-X") + 1]
        )
        step = self.calls
        statuses = (201, 200, 200)
        body = (
            FINAL_BODY
            if (
                step == 3
                and self.owner.wrong_body_at
                != self.owner.total_runs
            )
            else f"step-{step}".encode("ascii")
        )
        web = self.work / "web"
        web.mkdir(parents=True, exist_ok=True)
        timeline_path = web / "timeline.json"
        if timeline_path.exists():
            timeline = json.loads(timeline_path.read_text())
        else:
            timeline = {
                "events": [],
                "omitted_events": 0,
                "schema_version": 1,
            }
        timeline["events"].append(
            {
                "artifact": (
                    "/work/web/browser.json"
                    if channel == "browser"
                    else "/work/web/response.json"
                ),
                "cookie_transition": {
                    "added": [f"cookie-{role}"],
                    "removed": [],
                    "updated": [],
                },
                "method": method,
                "ordinal": step,
                "recorded_utc": "2026-07-31T00:00:00+00:00",
                "request": {"host": "vulnerable.test"},
                "security_headers": [],
                "session": (
                    "admin"
                    if self.owner.cross_role_at
                    == self.owner.total_runs
                    else role
                ),
                "source": channel,
                "status": statuses[step - 1],
            }
        )
        timeline_path.write_bytes(_json_bytes(timeline))
        if channel == "browser":
            (web / "browser.html").write_bytes(body)
            (web / "browser.json").write_bytes(
                _json_bytes(
                    {
                        "ok": True,
                        "response": {
                            "html_truncated": False,
                            "status": statuses[step - 1],
                        },
                    }
                )
            )
        else:
            (web / "body.bin").write_bytes(body)
            (web / "response.json").write_bytes(
                _json_bytes(
                    {
                        "ok": True,
                        "response": {
                            "status": statuses[step - 1],
                            "truncated": False,
                        },
                    }
                )
            )
        if self.owner.tamper_capture_at == self.owner.total_runs:
            captures = list(
                (
                    self.owner.engine.store.challenge_paths(
                        self.owner.identity
                    ).artifacts
                    / "web-impact"
                    / "captures"
                ).glob("*.bin")
            )
            if captures:
                captures[0].chmod(0o600)
                captures[0].write_bytes(b"tampered")
                captures[0].chmod(0o400)
        return SandboxResult(
            run_id=f"run-{self.owner.total_runs:08d}",
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

    def run_clean_proof(self, *args, **kwargs):
        raise AssertionError("Web hot path uses the normal sandbox boundary")

    def start_job(self, *args, **kwargs):
        raise AssertionError("not used")

    def job_status(self, *args, **kwargs):
        raise AssertionError("not used")

    def job_log(self, *args, **kwargs):
        raise AssertionError("not used")

    def cancel_job(self, *args, **kwargs):
        raise AssertionError("not used")


class _Coordinator:
    def __init__(self, identity: ChallengeIdentity) -> None:
        self.identity = identity
        self.engine: ChallengeEngine
        self.source: Path
        self.total_runs = 0
        self.specs = []
        self.policies = []
        self.mutate_source_at: int | None = None
        self.tamper_request_at: int | None = None
        self.cross_role_at: int | None = None
        self.tamper_capture_at: int | None = None
        self.interrupt_at: int | None = None
        self.wrong_body_at: int | None = None

    def factory(self, _state, work, policy):
        return _WebSandbox(self, work, policy)


class WebImpactHotPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.identity = ChallengeIdentity(
            "Web CTF",
            "web",
            "impact",
        )
        self.coordinator = _Coordinator(self.identity)
        config = replace(
            load_config(self.root),
            runtime=replace(
                load_config(self.root).runtime,
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
        self.coordinator.source = incoming / "app.py"
        self.coordinator.source.write_bytes(b"print('web challenge')\n")
        state = self.engine.add_challenge(
            self.identity,
            prompt="prove the declared impact",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        state = self.engine.add_network_target(
            self.identity,
            "https://vulnerable.test",
            docker_network="ctf-proxy-net",
            enforcement="proxy",
        )
        target = state.targets[-1]
        state = self.engine.select_network_target(
            self.identity,
            target.id,
        )
        self.target = next(
            item for item in state.targets if item.id == target.id
        )
        self.workspace = self.engine._workspace(state)
        routes = (
            ("route-create.txt", b"/create\n"),
            ("route-approve.txt", b"/approve\n"),
            ("route-extract.txt", b"/extract\n"),
        )
        driver_inputs = []
        for name, payload in routes:
            path = self.workspace / name
            path.write_bytes(payload)
            driver_inputs.append(
                WebImpactDriverInput(
                    locator=name,
                    sha256=_sha256(payload),
                    size_bytes=len(payload),
                )
            )
        self.steps = (
            WebImpactDriverStep(
                ordinal=1,
                channel="http",
                role="user",
                method="POST",
                route=driver_inputs[0],
                body=None,
                follow=False,
                insecure=False,
                timeout_seconds=10,
            ),
            WebImpactDriverStep(
                ordinal=2,
                channel="browser",
                role="admin",
                method="GET",
                route=driver_inputs[1],
                body=None,
                follow=False,
                insecure=False,
                timeout_seconds=10,
            ),
            WebImpactDriverStep(
                ordinal=3,
                channel="http",
                role="attacker",
                method="GET",
                route=driver_inputs[2],
                body=None,
                follow=False,
                insecure=False,
                timeout_seconds=10,
            ),
        )
        approved = {
            "binding_sha256": web_impact_target_binding_sha256(
                self.target
            ),
            "generation": self.target.generation,
            "kind": WEB_IMPACT_ALLOWLISTED_TARGET_KIND,
        }
        trace_contract = web_impact_trace_contract_sha256(
            source_kind="request_parameter",
            source_pointer_sha256=_digest("source"),
            sink_kind="response_body",
            sink_pointer_sha256=_digest("sink"),
            runtime_step_ordinal=3,
        )
        state = self.engine.store.load(self.identity)
        operator = {
            "authorized_target": approved,
            "differential": None,
            "identities": [
                {
                    "principal_binding_sha256": _digest(
                        f"principal:{role}"
                    ),
                    "role": role,
                }
                for role in WEB_IDENTITY_ROLES
            ],
            "oracle": {
                "expected_response_sha256": _sha256(FINAL_BODY),
                "expected_response_size_bytes": len(FINAL_BODY),
                "expected_status": 200,
                "impact_kind": "authorization_bypass",
                "sink_step_ordinal": 3,
            },
            "protocol": WEB_IMPACT_OPERATOR_SPEC_PROTOCOL,
            "runtime_image_digest": IMAGE_DIGEST,
            "schema_version": 1,
            "source_manifest_sha256": state.metadata[
                "source_manifest_sha256"
            ],
            "source_sink": {
                "runtime_step_ordinal": 3,
                "sink_kind": "response_body",
                "sink_pointer_sha256": _digest("sink"),
                "source_kind": "request_parameter",
                "source_pointer_sha256": _digest("source"),
                "trace_contract_sha256": trace_contract,
            },
            "timeline": [
                {
                    "channel": step.channel,
                    "expected_status": status,
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
                for step, status in zip(
                    self.steps,
                    (201, 200, 200),
                    strict=True,
                )
            ],
        }
        self.operator_payload = _json_bytes(operator)
        (self.workspace / "impact-spec.json").write_bytes(
            self.operator_payload
        )
        driver = WebImpactDriverManifest(
            operator_spec_sha256=_sha256(self.operator_payload),
            vulnerable_target_id=self.target.id,
            control_target_id=None,
            steps=self.steps,
        )
        self.driver_payload = driver.canonical_bytes
        (self.workspace / "impact-driver.json").write_bytes(
            self.driver_payload
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _prove(self):
        return self.engine.prove_web_impact(
            self.identity,
            operator_spec_locator="impact-spec.json",
            driver_locator="impact-driver.json",
            timeout_seconds=120,
        )

    def _latest_attempt(self):
        state = self.engine.store.load(self.identity)
        attempts = state.extra["web_impact_preissues"]
        return state, next(reversed(attempts.values()))

    def test_success_is_preissued_and_authorizes_only_fact_progress(self):
        before = self.engine.store.load(self.identity)
        state, evaluation = self._prove()

        self.assertTrue(evaluation.confirmed)
        self.assertEqual(self.coordinator.total_runs, 9)
        self.assertEqual(len(state.facts), len(before.facts) + 1)
        self.assertIs(
            state.facts[-1].provenance,
            Provenance.EXECUTED,
        )
        self.assertEqual(
            len(state.progress_markers),
            len(before.progress_markers) + 1,
        )
        self.assertEqual(state.candidates, before.candidates)
        self.assertEqual(state.submissions, before.submissions)
        self.assertIs(state.status, before.status)
        validate_web_impact_state_graph(state)
        attempt = next(
            reversed(state.extra["web_impact_preissues"].values())
        )
        self.assertEqual(attempt["status"], "completed")
        self.assertEqual(len(attempt["replays"]), 3)
        self.assertFalse(
            (
                self.engine.store.challenge_paths(self.identity).runtime
                / "web-impact-live"
                / attempt["attempt_id"]
            ).exists()
        )
        self.assertTrue(
            all(
                policy.enforcement == "proxy"
                and len(policy.allow_targets) == 1
                for policy in self.coordinator.policies
            )
        )
        encoded = _json_bytes(state.to_dict())
        self.assertNotIn(FINAL_BODY, encoded)

    def test_driver_bool_int_and_noncanonical_documents_reject(self):
        document = json.loads(self.driver_payload)
        document["steps"][0]["timeout_seconds"] = True
        with self.assertRaises(WebImpactDriverError):
            parse_web_impact_driver_manifest(
                _json_bytes(document),
                operator_spec_payload=self.operator_payload,
            )
        with self.assertRaisesRegex(
            WebImpactDriverError,
            "not_canonical",
        ):
            parse_web_impact_driver_manifest(
                self.driver_payload.rstrip(b"\n") + b" \n",
                operator_spec_payload=self.operator_payload,
            )

    def test_preissue_commit_failure_removes_attempt_tree_and_runs(self):
        paths = self.engine.store.challenge_paths(self.identity)
        attempt_family = paths.artifacts / "web-impact"
        before_files = {
            path.relative_to(attempt_family).as_posix()
            for path in attempt_family.rglob("*")
            if path.is_file()
        } if attempt_family.exists() else set()
        before_runs = {path.name for path in paths.runs.iterdir()}
        original_update = self.engine.store.update

        def reject_preissue(*args, **kwargs):
            apply = args[1]
            if getattr(apply, "__name__", "") == "commit_preissue":
                raise RuntimeError("synthetic preissue commit failure")
            return original_update(*args, **kwargs)

        with (
            mock.patch.object(
                self.engine.store,
                "update",
                side_effect=reject_preissue,
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "synthetic preissue commit failure",
            ),
        ):
            self._prove()
        after_files = {
            path.relative_to(attempt_family).as_posix()
            for path in attempt_family.rglob("*")
            if path.is_file()
        } if attempt_family.exists() else set()
        self.assertEqual(after_files, before_files)
        self.assertEqual(
            {path.name for path in paths.runs.iterdir()},
            before_runs,
        )

    def test_cli_exposes_explicit_spec_driver_and_timeout(self):
        parsed = cli.build_parser().parse_args(
            [
                "web-prove",
                self.identity.contest_id,
                self.identity.category,
                self.identity.challenge_id,
                "--spec",
                "impact-spec.json",
                "--driver",
                "impact-driver.json",
                "--hypothesis",
                "H-web-1",
                "--timeout",
                "120",
            ]
        )
        self.assertEqual(parsed.command, "web-prove")
        self.assertEqual(parsed.spec, "impact-spec.json")
        self.assertEqual(parsed.driver, "impact-driver.json")
        self.assertEqual(parsed.hypothesis, ["H-web-1"])
        self.assertEqual(parsed.timeout, 120)

    def test_identity_epoch_reset_removes_all_prior_role_state(self):
        state = self.engine.store.load(self.identity)
        scope = ChallengeScope(
            contest_id=self.identity.contest_id,
            category=self.identity.category,
            challenge_id=self.identity.challenge_id,
            challenge_dir=self.engine.challenge_input(self.identity),
            work_dir=self.engine._workspace(state),
        )
        attacker, timeline = resolve_private_web_mounts(
            scope,
            "attacker",
        )
        (attacker / "cookies.json").write_bytes(b"secret-cookie")
        (timeline / "events.jsonl").write_bytes(b"secret-event")
        epoch = _digest("epoch-reset")
        reset_private_web_identity_state(scope, epoch)
        fresh_attacker, fresh_timeline = resolve_private_web_mounts(
            scope,
            "attacker",
        )
        self.assertEqual(tuple(fresh_attacker.iterdir()), ())
        self.assertEqual(tuple(fresh_timeline.iterdir()), ())
        self.assertEqual(
            private_web_identity_epoch_sha256(scope),
            epoch,
        )

    def test_source_mutation_rejects_and_terminalizes(self):
        self.coordinator.mutate_source_at = 2
        with self.assertRaisesRegex(
            Exception,
            "source_manifest_changed",
        ):
            self._prove()
        state, attempt = self._latest_attempt()
        self.assertEqual(attempt["status"], "interrupted")
        self.assertFalse(
            any(
                fact.extra.get("web_impact_state")
                for fact in state.facts
            )
        )

    def test_preissued_request_toctou_rejects_and_terminalizes(self):
        self.coordinator.tamper_request_at = 1
        with self.assertRaisesRegex(
            Exception,
            "preissued_request_unavailable",
        ):
            self._prove()
        state, attempt = self._latest_attempt()
        self.assertEqual(attempt["status"], "interrupted")
        self.assertFalse(
            any(
                fact.extra.get("web_impact_state")
                for fact in state.facts
            )
        )

    def test_one_failed_replay_cannot_be_cherry_picked(self):
        self.coordinator.wrong_body_at = 9
        before = self.engine.store.load(self.identity)
        state, evaluation = self._prove()
        self.assertFalse(evaluation.confirmed)
        self.assertEqual(self.coordinator.total_runs, 9)
        self.assertEqual(state.facts, before.facts)
        self.assertEqual(
            state.progress_markers,
            before.progress_markers,
        )
        attempt = next(
            reversed(state.extra["web_impact_preissues"].values())
        )
        self.assertEqual(attempt["status"], "completed")

    def test_role_session_cross_contamination_rejects(self):
        self.coordinator.cross_role_at = 1
        with self.assertRaisesRegex(
            Exception,
            "timeline_event_binding_mismatch",
        ):
            self._prove()
        _state, attempt = self._latest_attempt()
        self.assertEqual(attempt["status"], "interrupted")

    def test_capture_tamper_rejects_before_final_replace(self):
        self.coordinator.tamper_capture_at = 9
        with self.assertRaisesRegex(
            Exception,
            "capture_changed_before_commit|hash mismatch",
        ):
            self._prove()
        state, attempt = self._latest_attempt()
        self.assertEqual(attempt["status"], "interrupted")
        self.assertFalse(
            any(
                fact.extra.get("web_impact_state")
                for fact in state.facts
            )
        )

    def test_keyboard_interrupt_is_terminalized_without_authority(self):
        self.coordinator.interrupt_at = 1
        with self.assertRaises(KeyboardInterrupt):
            self._prove()
        state, attempt = self._latest_attempt()
        self.assertEqual(attempt["status"], "interrupted")
        self.assertEqual(
            attempt["terminal"]["error_type"],
            "KeyboardInterrupt",
        )
        self.assertFalse(
            any(
                fact.extra.get("web_impact_state")
                for fact in state.facts
            )
        )

    def test_global_preissue_id_collision_rejects(self):
        # Force one generated graph id to collide while all issued replay
        # identities remain internally unique.
        sequence = [0]

        def colliding_id(prefix: str) -> str:
            sequence[0] += 1
            if prefix == "A-web-spec":
                return "G-initial-triage"
            return f"{prefix}-test-{sequence[0]:04d}"

        with mock.patch(
            "ctf_os.engine.web_impact_hotpath._new_id",
            side_effect=colliding_id,
        ):
            with self.assertRaisesRegex(
                Exception,
                "identifiers collide",
            ):
                self._prove()


if __name__ == "__main__":
    unittest.main()
