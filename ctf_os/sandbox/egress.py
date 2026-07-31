"""Built-in challenge-scoped restricted egress boundary.

The challenge container is attached only to an internal Docker network.  A
separate, least-privilege proxy container is the sole member that is also
attached to the configured upstream network.  The proxy validates every
HTTP/SOCKS destination against the exact policy allowlist.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ctf_os.images import effective_image_reference

from .types import ChallengeScope, NetworkPolicy, SandboxError, ScopeError

Runner = Callable[..., subprocess.CompletedProcess[str]]

_PROXY_ALIAS = "ctfos-egress"
_HTTP_PORT = 18080
_SOCKS_PORT = 1080
_CONTROL_PORT = 18081
_MAX_CONTROL_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class RestrictedEgressRuntime:
    """Exact runtime binding injected into one challenge command."""

    network: str
    proxy_container: str
    policy_fingerprint: str

    @property
    def environment(self) -> Mapping[str, str]:
        http_proxy = f"http://{_PROXY_ALIAS}:{_HTTP_PORT}"
        socks_proxy = f"socks5h://{_PROXY_ALIAS}:{_SOCKS_PORT}"
        no_proxy = "localhost,127.0.0.1,::1"
        return {
            "ALL_PROXY": socks_proxy,
            "HTTPS_PROXY": http_proxy,
            "HTTP_PROXY": http_proxy,
            "NO_PROXY": no_proxy,
            "all_proxy": socks_proxy,
            "https_proxy": http_proxy,
            "http_proxy": http_proxy,
            "no_proxy": no_proxy,
            "CTFOS_EGRESS_CONTROL": (f"http://{_PROXY_ALIAS}:{_CONTROL_PORT}"),
            "CTFOS_EGRESS_POLICY_SHA256": self.policy_fingerprint,
        }


class RestrictedEgressBoundary:
    """Provision and attest one built-in restricted Docker proxy boundary."""

    def __init__(
        self,
        scope: ChallengeScope,
        policy: NetworkPolicy,
        *,
        image: str,
        image_digest: str | None,
        runner: Runner = subprocess.run,
        docker: str = "docker",
    ) -> None:
        if policy.enforcement != "builtin":
            raise ValueError("restricted egress boundary requires builtin enforcement")
        self.scope = scope
        self.policy = policy
        self.image = image
        self.image_digest = image_digest
        self.image_reference = effective_image_reference(image, image_digest)
        self.runner = runner
        self.docker = docker
        policy_document = {
            "allow_targets": [target.as_text() for target in policy.allow_targets],
            "http_burst": policy.http_burst,
            "http_requests_per_second": (policy.http_requests_per_second),
            "scope": scope.fingerprint,
            "upstream_network": policy.docker_network,
        }
        canonical = json.dumps(
            policy_document,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        self.policy_fingerprint = hashlib.sha256(canonical).hexdigest()
        suffix = f"{scope.fingerprint[:12]}-{self.policy_fingerprint[:10]}"
        self.internal_network = f"ctfos-bnd-{suffix}"
        self.proxy_container = f"ctfos-proxy-{suffix}"

    @staticmethod
    def _bounded(value: str, maximum: int = 4096) -> str:
        encoded = value.encode("utf-8", errors="replace")
        if len(encoded) <= maximum:
            return value
        return encoded[-maximum:].decode("utf-8", errors="replace")

    def _run(
        self,
        argv: Sequence[str],
        *,
        timeout: float = 30,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return self.runner(
                list(argv),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as error:
            raise SandboxError("docker executable was not found") from error
        except subprocess.TimeoutExpired as error:
            raise SandboxError(
                "restricted egress Docker control operation timed out"
            ) from error
        except OSError as error:
            raise SandboxError(
                f"restricted egress Docker control operation failed: {error}"
            ) from error

    def _inspect(
        self,
        object_type: str,
        name: str,
    ) -> dict[str, Any] | None:
        result = self._run(
            [self.docker, object_type, "inspect", name],
        )
        if result.returncode != 0:
            return None
        if (
            len((result.stdout or "").encode("utf-8", errors="replace"))
            > _MAX_CONTROL_BYTES
        ):
            raise SandboxError("restricted egress Docker inspect output exceeded 1 MiB")
        try:
            values = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise SandboxError(
                "restricted egress Docker inspect returned invalid JSON"
            ) from error
        if (
            not isinstance(values, list)
            or len(values) != 1
            or not isinstance(values[0], dict)
        ):
            raise SandboxError(
                "restricted egress Docker inspect returned an unexpected result"
            )
        return values[0]

    @property
    def _labels(self) -> dict[str, str]:
        return {
            "ctfos.boundary": "builtin-v1",
            "ctfos.managed": "true",
            "ctfos.policy": self.policy_fingerprint,
            "ctfos.scope": self.scope.fingerprint,
        }

    def _verify_network(self, details: Mapping[str, Any]) -> None:
        labels = details.get("Labels")
        options = details.get("Options")
        if (
            details.get("Name") != self.internal_network
            or details.get("Driver") != "bridge"
            or details.get("Internal") is not True
            or details.get("Attachable") is not False
            or not isinstance(labels, Mapping)
            or any(labels.get(key) != value for key, value in self._labels.items())
            or not isinstance(options, Mapping)
            or options.get("com.docker.network.bridge.enable_ip_masquerade") != "false"
        ):
            raise ScopeError(
                "restricted egress network does not match its challenge policy"
            )

    def _proxy_command(self) -> tuple[str, ...]:
        command = [
            "serve",
            "--listen-interface",
            "eth0",
            "--http-port",
            str(_HTTP_PORT),
            "--socks-port",
            str(_SOCKS_PORT),
            "--control-port",
            str(_CONTROL_PORT),
            "--http-rate",
            str(self.policy.http_requests_per_second),
            "--http-burst",
            str(self.policy.http_burst),
        ]
        for target in self.policy.allow_targets:
            command.extend(["--allow-target", target.as_text()])
        return tuple(command)

    def _verify_proxy(self, details: Mapping[str, Any]) -> None:
        config = details.get("Config")
        host_config = details.get("HostConfig")
        state = details.get("State")
        network_settings = details.get("NetworkSettings")
        if not all(
            isinstance(value, Mapping)
            for value in (config, host_config, state, network_settings)
        ):
            raise ScopeError("restricted egress proxy inspect shape is invalid")
        assert isinstance(config, Mapping)
        assert isinstance(host_config, Mapping)
        assert isinstance(state, Mapping)
        assert isinstance(network_settings, Mapping)
        labels = config.get("Labels")
        networks = network_settings.get("Networks")
        cap_drop = host_config.get("CapDrop")
        security_opt = host_config.get("SecurityOpt")
        if (
            config.get("Image") != self.image_reference
            or (
                self.image_digest is not None
                and details.get("Image") != self.image_digest
            )
            or config.get("Entrypoint") != ["/usr/local/bin/ctf-egress-proxy"]
            or config.get("Cmd") != list(self._proxy_command())
            or config.get("User") != "65534:65534"
            or not isinstance(labels, Mapping)
            or any(labels.get(key) != value for key, value in self._labels.items())
            or host_config.get("ReadonlyRootfs") is not True
            or not isinstance(cap_drop, list)
            or "ALL" not in cap_drop
            or not isinstance(security_opt, list)
            or not any(
                str(value).startswith("no-new-privileges") for value in security_opt
            )
            or host_config.get("Privileged") is not False
            or not isinstance(networks, Mapping)
            or set(networks) != {self.internal_network, self.policy.docker_network}
            or state.get("Running") is not True
        ):
            raise ScopeError(
                "restricted egress proxy does not match its challenge policy"
            )
        internal = networks[self.internal_network]
        if not isinstance(internal, Mapping) or _PROXY_ALIAS not in (
            internal.get("Aliases") or []
        ):
            raise ScopeError(
                "restricted egress proxy is missing its internal-only alias"
            )

    def _ensure_network(self) -> None:
        details = self._inspect("network", self.internal_network)
        if details is None:
            argv = [
                self.docker,
                "network",
                "create",
                "--driver",
                "bridge",
                "--internal",
                "--opt",
                "com.docker.network.bridge.enable_ip_masquerade=false",
            ]
            for key, value in sorted(self._labels.items()):
                argv.extend(["--label", f"{key}={value}"])
            argv.append(self.internal_network)
            created = self._run(argv)
            if created.returncode != 0:
                # A concurrent process may have created the exact name.
                details = self._inspect("network", self.internal_network)
                if details is None:
                    detail = self._bounded(
                        created.stderr or created.stdout or ""
                    ).strip()
                    raise SandboxError(
                        "could not create restricted egress network"
                        + (f": {detail}" if detail else "")
                    )
            else:
                details = self._inspect("network", self.internal_network)
        if details is None:
            raise SandboxError("restricted egress network disappeared after creation")
        self._verify_network(details)

    def _proxy_run_argv(self) -> list[str]:
        argv = [
            self.docker,
            "run",
            "--detach",
            "--name",
            self.proxy_container,
        ]
        for key, value in sorted(self._labels.items()):
            argv.extend(["--label", f"{key}={value}"])
        argv.extend(
            [
                "--network",
                self.internal_network,
                "--network-alias",
                _PROXY_ALIAS,
                "--user",
                "65534:65534",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec,size=16m",
                "--cpus",
                "0.50",
                "--memory",
                "192m",
                "--pids-limit",
                "96",
                "--security-opt",
                "no-new-privileges",
                "--cap-drop",
                "ALL",
                "--env",
                "HOME=/tmp",
                "--env",
                "PYTHONDONTWRITEBYTECODE=1",
                "--entrypoint",
                "/usr/local/bin/ctf-egress-proxy",
                self.image_reference,
                *self._proxy_command(),
            ]
        )
        return argv

    def _ensure_proxy(self) -> None:
        details = self._inspect("container", self.proxy_container)
        if details is None:
            created = self._run(self._proxy_run_argv(), timeout=60)
            if created.returncode != 0:
                details = self._inspect("container", self.proxy_container)
                if details is None:
                    detail = self._bounded(
                        created.stderr or created.stdout or ""
                    ).strip()
                    raise SandboxError(
                        "could not start restricted egress proxy"
                        + (f": {detail}" if detail else "")
                    )
        attached = self._run(
            [
                self.docker,
                "network",
                "connect",
                self.policy.docker_network,
                self.proxy_container,
            ]
        )
        if attached.returncode != 0:
            refreshed = self._inspect("container", self.proxy_container)
            network_settings = (
                refreshed.get("NetworkSettings")
                if isinstance(refreshed, Mapping)
                else None
            )
            networks = (
                network_settings.get("Networks")
                if isinstance(network_settings, Mapping)
                else None
            )
            if (
                not isinstance(networks, Mapping)
                or self.policy.docker_network not in networks
            ):
                detail = self._bounded(attached.stderr or attached.stdout or "").strip()
                raise SandboxError(
                    "could not attach restricted egress proxy upstream"
                    + (f": {detail}" if detail else "")
                )
        details = self._inspect("container", self.proxy_container)
        if details is None:
            raise SandboxError(
                "restricted egress proxy disappeared during provisioning"
            )
        self._verify_proxy(details)

        deadline = time.monotonic() + 10
        while True:
            health = self._run(
                [
                    self.docker,
                    "container",
                    "exec",
                    self.proxy_container,
                    "/usr/local/bin/ctf-egress-proxy",
                    "healthcheck",
                    "--listen-interface",
                    "eth0",
                    "--control-port",
                    str(_CONTROL_PORT),
                ],
                timeout=5,
            )
            if health.returncode == 0:
                break
            if time.monotonic() >= deadline:
                detail = self._bounded(health.stderr or health.stdout or "").strip()
                raise SandboxError(
                    "restricted egress proxy did not become healthy"
                    + (f": {detail}" if detail else "")
                )
            time.sleep(0.05)

    def ensure(self) -> RestrictedEgressRuntime:
        """Provision and re-attest the exact internal network and proxy."""

        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,62}", self.internal_network):
            raise ScopeError("generated restricted egress network is invalid")
        self._ensure_network()
        self._ensure_proxy()
        return RestrictedEgressRuntime(
            network=self.internal_network,
            proxy_container=self.proxy_container,
            policy_fingerprint=self.policy_fingerprint,
        )
