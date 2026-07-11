"""Per-attempt Docker sandbox primitives for CTF-OS.

The package only constructs and runs Docker argv lists.  It never passes a
challenge command to a host shell.
"""

from .container import (
    SandboxContainer,
    SandboxScope,
    SandboxSpec,
    build_container_name,
    build_ctf_exec_argv,
    build_docker_exec_argv,
    build_docker_run_argv,
    build_docker_staging_scrub_argv,
    build_labels,
    create_ctf_exec_helper,
)
from .broker import AttemptCommandBroker, BrokerError, BrokerResponse, broker_transport_supported
from .network_policy import AllowedEndpoint, RemoteEndpoint, RemotePolicyError, parse_remote_endpoints, resolve_remote_endpoints
from .docker_cli import CommandResult, DockerCli, RecordingCommandRunner
from .exec import ResolvedAttempt, SandboxExecError, execute_attempt_command, resolve_local_attempt
from .pool import DockerSandboxPool, PoolCapacityError, SandboxPathError

__all__ = [
    "CommandResult",
    "DockerCli",
    "DockerSandboxPool",
    "PoolCapacityError",
    "RecordingCommandRunner",
    "ResolvedAttempt",
    "SandboxContainer",
    "SandboxExecError",
    "SandboxPathError",
    "SandboxScope",
    "SandboxSpec",
    "AttemptCommandBroker",
    "BrokerError",
    "BrokerResponse",
    "broker_transport_supported",
    "AllowedEndpoint",
    "RemoteEndpoint",
    "RemotePolicyError",
    "parse_remote_endpoints",
    "resolve_remote_endpoints",
    "build_container_name",
    "build_ctf_exec_argv",
    "build_docker_exec_argv",
    "build_docker_run_argv",
    "build_docker_staging_scrub_argv",
    "build_labels",
    "create_ctf_exec_helper",
    "execute_attempt_command",
    "resolve_local_attempt",
]
