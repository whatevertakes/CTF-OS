from __future__ import annotations

import copy
import importlib.machinery
import importlib.util
import json
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from ctf_os.director.resources import ResourceVector
from ctf_os.engine.challenge import (
    ChallengeEngine,
    EngineError,
    SessionAlreadyRunning,
)
from ctf_os.models import ChallengeIdentity
from ctf_os.sandbox.docker import DockerSandboxBackend
from ctf_os.sandbox.egress import (
    RestrictedEgressBoundary,
    RestrictedEgressRuntime,
)
from ctf_os.sandbox.types import (
    ChallengeScope,
    CommandSpec,
    NetworkDenied,
    NetworkPolicy,
    NetworkTarget,
    SandboxResult,
    ScopeError,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.store import ChallengeLock

ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str, relative: str):
    loader = importlib.machinery.SourceFileLoader(
        name,
        str(ROOT / relative),
    )
    spec = importlib.util.spec_from_loader(name, loader)
    if spec is None:
        raise RuntimeError(f"could not load {relative}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


class _DockerBoundaryRunner:
    def __init__(self) -> None:
        self.networks: dict[str, dict[str, object]] = {}
        self.containers: dict[str, dict[str, object]] = {}
        self.calls: list[list[str]] = []

    @staticmethod
    def _result(
        argv: list[str],
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            argv,
            returncode,
            stdout=stdout,
            stderr=stderr,
        )

    @staticmethod
    def _option_values(argv: list[str], option: str) -> list[str]:
        return [
            argv[index + 1] for index, value in enumerate(argv[:-1]) if value == option
        ]

    def __call__(self, argv, **_kwargs):
        values = list(argv)
        self.calls.append(values)
        if values[:3] == ["docker", "network", "inspect"]:
            details = self.networks.get(values[3])
            if details is None:
                return self._result(values, 1, stderr="not found")
            return self._result(values, stdout=json.dumps([details]))
        if values[:3] == ["docker", "container", "inspect"]:
            reference = values[3]
            details = next(
                (
                    item
                    for name, item in self.containers.items()
                    if reference in {name, item.get("Id")}
                ),
                None,
            )
            if details is None:
                return self._result(values, 1, stderr="not found")
            return self._result(values, stdout=json.dumps([details]))
        if values[:3] == ["docker", "network", "create"]:
            name = values[-1]
            labels = dict(
                item.split("=", 1) for item in self._option_values(values, "--label")
            )
            self.networks[name] = {
                "Attachable": False,
                "Driver": "bridge",
                "Internal": True,
                "Labels": labels,
                "Name": name,
                "Options": {"com.docker.network.bridge.enable_ip_masquerade": "false"},
            }
            return self._result(values, stdout="network-id\n")
        if values[:2] == ["docker", "run"]:
            name = self._option_values(values, "--name")[0]
            network = self._option_values(values, "--network")[0]
            alias = self._option_values(values, "--network-alias")[0]
            labels = dict(
                item.split("=", 1) for item in self._option_values(values, "--label")
            )
            entrypoint = self._option_values(values, "--entrypoint")[0]
            image_index = values.index(entrypoint) + 1
            image = values[image_index]
            command = values[image_index + 1 :]
            self.containers[name] = {
                "Config": {
                    "Cmd": command,
                    "Entrypoint": [entrypoint],
                    "Image": image,
                    "Labels": labels,
                    "User": "65534:65534",
                },
                "HostConfig": {
                    "CapDrop": ["ALL"],
                    "Privileged": False,
                    "ReadonlyRootfs": True,
                    "SecurityOpt": ["no-new-privileges"],
                },
                "Id": "a" * 64,
                "Image": "local-image-id",
                "Name": f"/{name}",
                "NetworkSettings": {
                    "Networks": {
                        network: {"Aliases": [alias]},
                    }
                },
                "State": {
                    "Dead": False,
                    "Paused": False,
                    "Pid": 123,
                    "Restarting": False,
                    "Running": True,
                    "Status": "running",
                },
            }
            return self._result(values, stdout="container-id\n")
        if values[:3] == ["docker", "container", "start"]:
            reference = values[3]
            name = next(
                name
                for name, details in self.containers.items()
                if reference in {name, details["Id"]}
            )
            state = self.containers[name]["State"]
            state.update(
                {
                    "Dead": False,
                    "Paused": False,
                    "Pid": 123,
                    "Restarting": False,
                    "Running": True,
                    "Status": "running",
                }
            )
            return self._result(values, stdout=f"{name}\n")
        if values[:3] == ["docker", "network", "connect"]:
            network, reference = values[3:5]
            name = next(
                name
                for name, details in self.containers.items()
                if reference in {name, details["Id"]}
            )
            networks = self.containers[name]["NetworkSettings"]["Networks"]
            if network in networks:
                return self._result(values, 1, stderr="already connected")
            networks[network] = {"Aliases": [name]}
            return self._result(values)
        if values[:3] == ["docker", "container", "exec"]:
            return self._result(values)
        return self._result(values, 1, stderr="unexpected command")


class RestrictedEgressBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        root = Path(self.temporary_directory.name)
        challenge = root / "challenge"
        work = root / "work"
        challenge.mkdir()
        work.mkdir()
        self.scope = ChallengeScope.create(
            contest_id="contest",
            category="web",
            challenge_id="challenge",
            challenge_dir=challenge,
            work_dir=work,
        )
        self.policy = NetworkPolicy.allow(
            ("https://challenge.example:443",),
            docker_network="bridge",
            enforcement="builtin",
            http_requests_per_second=3.5,
            http_burst=7,
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_builtin_policy_requires_an_exact_port_and_defaults_deny(self) -> None:
        with self.assertRaisesRegex(ValueError, "explicit port"):
            NetworkPolicy.allow(
                ("https://challenge.example",),
                docker_network="bridge",
                enforcement="builtin",
            )
        self.assertEqual(
            self.policy.authorize(NetworkTarget.parse("https://challenge.example:443")),
            ":ctfos-builtin:",
        )
        with self.assertRaises(NetworkDenied):
            self.policy.authorize(NetworkTarget.parse("https://other.example:443"))

    def test_boundary_creates_internal_network_and_attests_proxy(self) -> None:
        runner = _DockerBoundaryRunner()
        boundary = RestrictedEgressBoundary(
            self.scope,
            self.policy,
            image="ctf-os:core",
            image_digest=None,
            runner=runner,
        )

        first = boundary.ensure()
        second = boundary.ensure()

        self.assertEqual(first, second)
        network = runner.networks[first.network]
        self.assertIs(network["Internal"], True)
        self.assertEqual(
            set(
                runner.containers[first.proxy_container]["NetworkSettings"]["Networks"]
            ),
            {first.network, "bridge"},
        )
        run_calls = [call for call in runner.calls if call[:2] == ["docker", "run"]]
        self.assertEqual(len(run_calls), 1)
        run = run_calls[0]
        self.assertIn("--cap-drop", run)
        self.assertIn("ALL", run)
        self.assertIn("--read-only", run)
        self.assertIn("--http-rate", run)
        self.assertIn("3.5", run)
        self.assertIn("--http-burst", run)
        self.assertIn("7", run)
        self.assertEqual(
            first.environment["HTTP_PROXY"],
            "http://ctfos-egress:18080",
        )
        self.assertEqual(
            first.environment["ALL_PROXY"],
            "socks5h://ctfos-egress:1080",
        )

    def test_existing_non_internal_network_fails_closed(self) -> None:
        runner = _DockerBoundaryRunner()
        boundary = RestrictedEgressBoundary(
            self.scope,
            self.policy,
            image="ctf-os:core",
            image_digest=None,
            runner=runner,
        )
        runner.networks[boundary.internal_network] = {
            "Attachable": False,
            "Driver": "bridge",
            "Internal": False,
            "Labels": boundary._labels,
            "Name": boundary.internal_network,
            "Options": {"com.docker.network.bridge.enable_ip_masquerade": "false"},
        }
        with self.assertRaisesRegex(ScopeError, "does not match"):
            boundary.ensure()

    def test_boundary_recovers_an_exact_exited_proxy(self) -> None:
        runner = _DockerBoundaryRunner()
        boundary = RestrictedEgressBoundary(
            self.scope,
            self.policy,
            image="ctf-os:core",
            image_digest=None,
            runner=runner,
        )
        expected = boundary.ensure()
        state = runner.containers[expected.proxy_container]["State"]
        state.update(
            {
                "Dead": False,
                "Paused": False,
                "Pid": 0,
                "Restarting": False,
                "Running": False,
                "Status": "exited",
            }
        )
        runner.calls.clear()

        recovered = boundary.ensure()

        self.assertEqual(recovered, expected)
        self.assertEqual(
            [
                call
                for call in runner.calls
                if call[:3] == ["docker", "container", "start"]
            ],
            [["docker", "container", "start", "a" * 64]],
        )
        self.assertFalse(
            any(call[:2] == ["docker", "run"] for call in runner.calls)
        )

    def test_boundary_does_not_restart_a_mismatched_exited_proxy(self) -> None:
        for mismatch in ("command", "labels", "networks"):
            with self.subTest(mismatch=mismatch):
                runner = _DockerBoundaryRunner()
                boundary = RestrictedEgressBoundary(
                    self.scope,
                    self.policy,
                    image="ctf-os:core",
                    image_digest=None,
                    runner=runner,
                )
                runtime = boundary.ensure()
                proxy = runner.containers[runtime.proxy_container]
                proxy["State"].update(
                    {
                        "Dead": False,
                        "Paused": False,
                        "Pid": 0,
                        "Restarting": False,
                        "Running": False,
                        "Status": "exited",
                    }
                )
                if mismatch == "command":
                    proxy["Config"]["Cmd"] = ["serve", "--allow-all"]
                elif mismatch == "labels":
                    proxy["Config"]["Labels"]["ctfos.scope"] = "another-scope"
                else:
                    proxy["NetworkSettings"]["Networks"]["unexpected"] = {
                        "Aliases": []
                    }
                runner.calls.clear()

                with self.assertRaisesRegex(ScopeError, "does not match"):
                    boundary.ensure()

                self.assertFalse(
                    any(
                        call[:3] == ["docker", "container", "start"]
                        for call in runner.calls
                    )
                )

    def test_boundary_does_not_restart_an_ambiguous_stopped_state(self) -> None:
        runner = _DockerBoundaryRunner()
        boundary = RestrictedEgressBoundary(
            self.scope,
            self.policy,
            image="ctf-os:core",
            image_digest=None,
            runner=runner,
        )
        runtime = boundary.ensure()
        runner.containers[runtime.proxy_container]["State"].update(
            {
                "Dead": False,
                "Paused": False,
                "Pid": 0,
                "Restarting": False,
                "Running": False,
                "Status": "created",
            }
        )
        runner.calls.clear()

        with self.assertRaisesRegex(ScopeError, "recoverable stopped state"):
            boundary.ensure()

        self.assertFalse(
            any(
                call[:3] == ["docker", "container", "start"]
                for call in runner.calls
            )
        )

    def test_boundary_rejects_name_replacement_after_exact_restart(self) -> None:
        class ReplacingRunner(_DockerBoundaryRunner):
            replace_after_connect = False

            def __call__(self, argv, **kwargs):
                values = list(argv)
                result = super().__call__(values, **kwargs)
                if (
                    self.replace_after_connect
                    and values[:3] == ["docker", "network", "connect"]
                ):
                    self.replace_after_connect = False
                    reference = values[4]
                    original_name = next(
                        name
                        for name, details in self.containers.items()
                        if reference in {name, details["Id"]}
                    )
                    original = self.containers.pop(original_name)
                    original["Name"] = "/renamed-exact-proxy"
                    self.containers["renamed-exact-proxy"] = original
                    replacement = copy.deepcopy(original)
                    replacement["Id"] = "b" * 64
                    replacement["Name"] = f"/{original_name}"
                    self.containers[original_name] = replacement
                return result

        runner = ReplacingRunner()
        boundary = RestrictedEgressBoundary(
            self.scope,
            self.policy,
            image="ctf-os:core",
            image_digest=None,
            runner=runner,
        )
        runtime = boundary.ensure()
        runner.containers[runtime.proxy_container]["State"].update(
            {
                "Dead": False,
                "Paused": False,
                "Pid": 0,
                "Restarting": False,
                "Running": False,
                "Status": "exited",
            }
        )
        runner.calls.clear()
        runner.replace_after_connect = True

        with self.assertRaisesRegex(
            ScopeError,
            "identity changed after recovery",
        ):
            boundary.ensure()

        self.assertIn(
            [
                "docker",
                "network",
                "connect",
                "bridge",
                "a" * 64,
            ],
            runner.calls,
        )
        self.assertFalse(
            any(
                call[:3] == ["docker", "container", "exec"]
                for call in runner.calls
            )
        )

    def test_backend_substitutes_internal_network_and_reserved_proxy_env(
        self,
    ) -> None:
        backend = DockerSandboxBackend(
            self.scope,
            network_policy=self.policy,
        )
        runtime = RestrictedEgressRuntime(
            network="ctfos-bnd-test",
            proxy_container="ctfos-proxy-test",
            policy_fingerprint="a" * 64,
        )
        spec = CommandSpec(
            ("true",),
            network_target=NetworkTarget.parse("https://challenge.example:443"),
            resource_request=ResourceVector(
                cpu=1,
                memory_mib=2048,
                network=1,
            ),
        )
        fake_boundary = mock.Mock()
        fake_boundary.ensure.return_value = runtime
        with mock.patch(
            "ctf_os.sandbox.docker.RestrictedEgressBoundary",
            return_value=fake_boundary,
        ):
            network, environment = backend._authorized_runtime(spec)
        self.assertEqual(network, "ctfos-bnd-test")
        self.assertEqual(
            environment["CTFOS_EGRESS_POLICY_SHA256"],
            "a" * 64,
        )
        fake_boundary.ensure.assert_called_once_with()


class RestrictedEgressEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.identity = ChallengeIdentity("contest", "web", "remote")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _configured_engine(self, sandbox_factory=None) -> ChallengeEngine:
        engine = ChallengeEngine(
            self.root,
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(
            self.identity,
            prompt="authorized challenge",
            budget_seconds=300,
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        state = engine.add_network_target(
            self.identity,
            "https://challenge.example:443",
            docker_network="bridge",
            enforcement="builtin",
            http_requests_per_second=1.25,
            http_burst=3,
        )
        target = state.targets[-1]
        engine.select_network_target(self.identity, target.id)
        return engine

    def test_target_rate_policy_is_durable_and_reconstructed(self) -> None:
        engine = self._configured_engine()
        state = engine.store.load(self.identity)
        target = state.targets[-1]
        self.assertEqual(
            target.extra["builtin_egress"],
            {
                "http_burst": 3,
                "http_requests_per_second": 1.25,
                "schema_version": 1,
            },
        )
        policy = engine._network_policy(state)
        self.assertEqual(policy.enforcement, "builtin")
        self.assertEqual(policy.http_requests_per_second, 1.25)
        self.assertEqual(policy.http_burst, 3)

    def test_explicit_smoke_uses_fake_sandbox_and_persists_result(self) -> None:
        calls: list[CommandSpec] = []

        class FakeSandbox:
            scope_fingerprint = "fake"

            def run(self, spec: CommandSpec) -> SandboxResult:
                calls.append(spec)
                document = {
                    "checks": [
                        {
                            "detail": {"address_count": 1},
                            "duration_ms": 1,
                            "mode": "dns",
                            "ok": True,
                        },
                        {
                            "detail": {"connect_ms": 1},
                            "duration_ms": 1,
                            "mode": "tcp",
                            "ok": True,
                        },
                    ],
                    "ok": True,
                    "protocol": "ctfos.network.smoke.v1",
                    "target": "https://challenge.example:443",
                }
                return SandboxResult(
                    run_id="run-00000001",
                    status="completed",
                    exit_code=0,
                    timed_out=False,
                    duration_ms=2,
                    stdout_summary=json.dumps(
                        document,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    stderr_summary="",
                    stdout_bytes=1,
                    stderr_bytes=0,
                    stdout_path="/work/stdout",
                    stderr_path="/work/stderr",
                )

        def sandbox_factory(_state, _work, policy):
            self.assertEqual(policy.enforcement, "builtin")
            return FakeSandbox()

        engine = self._configured_engine(sandbox_factory)
        state = engine.store.load(self.identity)
        target = state.targets[-1]
        checked = engine.smoke_network_target(
            self.identity,
            target.id,
            modes=("dns", "tcp"),
            timeout_seconds=2,
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].network_target.host, "challenge.example")
        self.assertEqual(calls[0].resource_request.network, 1)
        self.assertEqual(
            calls[0].argv,
            (
                "ctf-network-smoke",
                "--target",
                "https://challenge.example:443",
                "--path",
                "/",
                "--timeout",
                "2",
                "--mode",
                "dns",
                "--mode",
                "tcp",
            ),
        )
        self.assertIs(checked.targets[-1].last_preflight["ok"], True)
        self.assertIs(
            checked.targets[-1].last_preflight["remote_request_performed"],
            True,
        )

    def test_network_smoke_admits_before_lease_or_remote_sandbox(self) -> None:
        sandbox_calls = 0

        def sandbox_factory(_state, _work, _policy):
            nonlocal sandbox_calls
            sandbox_calls += 1
            raise AssertionError("quota rejection must precede sandbox setup")

        engine = self._configured_engine(sandbox_factory)
        state = engine.store.load(self.identity)
        target = state.targets[-1]
        engine.config = replace(
            engine.config,
            runtime=replace(
                engine.config.runtime,
                challenge_storage_quota_bytes=1,
            ),
        )

        with (
            mock.patch.object(
                engine.lease_broker,
                "acquire",
                wraps=engine.lease_broker.acquire,
            ) as acquire,
            self.assertRaisesRegex(EngineError, "storage quota"),
        ):
            engine.smoke_network_target(
                self.identity,
                target.id,
                modes=("dns",),
            )

        acquire.assert_not_called()
        self.assertEqual(sandbox_calls, 0)

    def test_network_smoke_obeys_the_challenge_session_lock(self) -> None:
        engine = self._configured_engine()
        state = engine.store.load(self.identity)
        target = state.targets[-1]
        lock = ChallengeLock(
            engine.store.challenge_paths(self.identity).runtime
            / "session.lock",
            timeout=0,
        ).acquire()
        try:
            with self.assertRaises(SessionAlreadyRunning):
                engine.smoke_network_target(
                    self.identity,
                    target.id,
                    modes=("dns",),
                )
        finally:
            lock.release()


class RestrictedProxyProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.proxy = _load_script(
            "ctfos_test_egress_proxy",
            "ctf-os-image/scripts/ctf-egress-proxy",
        )
        cls.smoke = _load_script(
            "ctfos_test_network_smoke",
            "ctf-os-image/scripts/ctf-network-smoke",
        )

    def test_per_target_bucket_counts_requests_inside_one_process(self) -> None:
        clock = [100.0]
        with mock.patch.object(
            self.proxy.time,
            "monotonic",
            side_effect=lambda: clock[0],
        ):
            policy = self.proxy.Policy(
                [self.proxy.Target.parse("http://allowed.example:80")],
                2.0,
                2,
            )
            target = policy.authorize("allowed.example", 80, "http")
            policy.charge(target)
            policy.charge(target)
            with self.assertRaisesRegex(
                self.proxy.ProxyError,
                "http_rate_limited",
            ):
                policy.charge(target)
            clock[0] += 0.5
            policy.charge(target)
        with self.assertRaisesRegex(
            self.proxy.ProxyError,
            "target_not_allowed",
        ):
            policy.authorize("denied.example", 80, "http")

    def test_http_target_cannot_be_reused_as_raw_or_connect_tunnel(self) -> None:
        policy = self.proxy.Policy(
            [self.proxy.Target.parse("http://127.0.0.1:8080")],
            100.0,
            100,
        )
        for transport in ("tcp", "https"):
            with self.subTest(transport=transport):
                with self.assertRaisesRegex(
                    self.proxy.ProxyError,
                    "target_not_allowed",
                ):
                    policy.authorize("127.0.0.1", 8080, transport)

        raw_policy = self.proxy.Policy(
            [self.proxy.Target.parse("tcp://127.0.0.1:8080")],
            100.0,
            100,
        )
        self.assertEqual(
            raw_policy.authorize("127.0.0.1", 8080, "tcp").scheme,
            "tcp",
        )
        with self.assertRaisesRegex(
            self.proxy.ProxyError,
            "target_not_allowed",
        ):
            raw_policy.authorize("127.0.0.1", 8080, "http")

    def test_plain_http_proxy_charges_each_request_not_command_start(
        self,
    ) -> None:
        policy = self.proxy.Policy(
            [self.proxy.Target.parse("http://allowed.example:80")],
            0.001,
            1,
        )
        server = SimpleNamespace(policy=policy)

        def one_request(expect_upstream: bool) -> bytes:
            client, proxy_side = socket.socketpair()
            upstream_proxy, upstream_server = socket.socketpair()

            def upstream() -> None:
                try:
                    if expect_upstream:
                        payload = upstream_server.recv(64 * 1024)
                        self.assertIn(
                            b"GET /inside-one-command HTTP/1.1",
                            payload,
                        )
                        upstream_server.sendall(
                            b"HTTP/1.1 204 No Content\r\n"
                            b"Content-Length: 0\r\n"
                            b"Connection: close\r\n\r\n"
                        )
                finally:
                    upstream_server.close()

            upstream_thread = threading.Thread(target=upstream)
            upstream_thread.start()

            def handle() -> None:
                try:
                    self.proxy.HTTPProxyHandler(
                        proxy_side,
                        ("local", 0),
                        server,
                    )
                finally:
                    proxy_side.close()

            handler_thread = threading.Thread(target=handle)
            with mock.patch.object(
                self.proxy,
                "connect_target",
                return_value=upstream_proxy,
            ):
                handler_thread.start()
                client.sendall(
                    b"GET http://allowed.example/inside-one-command HTTP/1.1\r\n"
                    b"Host: allowed.example\r\n\r\n"
                )
                response = bytearray()
                while True:
                    block = client.recv(4096)
                    if not block:
                        break
                    response.extend(block)
                handler_thread.join(timeout=2)
            client.close()
            upstream_proxy.close()
            upstream_thread.join(timeout=2)
            self.assertFalse(handler_thread.is_alive())
            self.assertFalse(upstream_thread.is_alive())
            return bytes(response)

        self.assertTrue(one_request(True).startswith(b"HTTP/1.1 204 "))
        self.assertTrue(
            one_request(False).startswith(b"HTTP/1.1 429 Too Many Requests")
        )

    def test_smoke_paths_return_stable_protocol_records(self) -> None:
        target = self.smoke.Target.parse("https://allowed.example:443")
        with mock.patch.object(
            self.smoke,
            "tls_check",
            return_value={
                "certificate_sha256": "a" * 64,
                "cipher": "cipher",
                "tls_version": "TLSv1.3",
            },
        ):
            result = self.smoke.run_check(
                "tls",
                target,
                1.0,
                "/",
            )
        self.assertEqual(result["mode"], "tls")
        self.assertIs(result["ok"], True)
        self.assertEqual(
            result["detail"]["certificate_sha256"],
            "a" * 64,
        )


if __name__ == "__main__":
    unittest.main()
