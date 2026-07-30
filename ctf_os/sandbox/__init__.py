"""Challenge-scoped CTF-OS sandbox API."""

from .client import (
    ChallengeSandboxClient,
    LocalChallengeSandboxClient,
    UnixChallengeSandboxClient,
)
from .docker import DockerLimits, DockerSandboxBackend
from .types import (
    ArtifactRef,
    BackgroundJobUnsupported,
    ChallengeScope,
    CommandSpec,
    JobLog,
    JobRef,
    JobState,
    JobStatus,
    NetworkDenied,
    NetworkPolicy,
    NetworkTarget,
    ProofInput,
    ProofOutput,
    SandboxError,
    SandboxResult,
    ScopeError,
    ensure_foreground_command,
)

__all__ = [
    "ArtifactRef",
    "BackgroundJobUnsupported",
    "ChallengeSandboxClient",
    "ChallengeScope",
    "CommandSpec",
    "DockerLimits",
    "DockerSandboxBackend",
    "JobLog",
    "JobRef",
    "JobState",
    "JobStatus",
    "LocalChallengeSandboxClient",
    "NetworkDenied",
    "NetworkPolicy",
    "NetworkTarget",
    "ProofInput",
    "ProofOutput",
    "SandboxError",
    "SandboxResult",
    "ScopeError",
    "UnixChallengeSandboxClient",
    "ensure_foreground_command",
]
