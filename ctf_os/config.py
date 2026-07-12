"""Configuration loading, validation, and deterministic local path resolution."""

from __future__ import annotations

from dataclasses import dataclass
import math
import os
from pathlib import Path
from typing import Any, Mapping

import yaml


class ConfigError(ValueError):
    """Raised when a CTF-OS configuration file is invalid."""


def load_yaml(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(f"configuration file not found: {config_path}")
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {config_path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigError(f"configuration root must be a mapping: {config_path}")
    return loaded


def default_config_mapping(
    contest_name: str,
    *,
    team_id: str | None = None,
    member_name: str = "local",
) -> dict[str, Any]:
    """Return a runnable mock-safe configuration for ``ctf-os init``.

    Model routing is deliberately disabled in this generated starter config:
    a real Codex run must be explicitly enabled with a reviewed routing file.
    Mock runs remain fully local and do not need Docker or Codex.
    """
    from .models import slugify

    resolved_team_id = team_id or f"{slugify(contest_name)}-team"
    resolved_member_name = member_name.strip() or "local"
    return {
        "mode": "local_node",
        "solver_mode": "cli_attempt_race",
        "contest": {
            "name": contest_name,
            "team_id": resolved_team_id,
            "flag_patterns": [r"FLAG\{[^}\r\n]+\}"],
        },
        "member": {
            "name": resolved_member_name,
            "display_name": resolved_member_name,
            "owned_categories": ["pwn", "web", "rev", "crypto", "forensic", "forensics", "misc", "cloud"],
        },
        "paths": {
            "incoming": "incoming",
            "output": f"output/{resolved_team_id}/{resolved_member_name}",
        },
        "solvers": {"codex": {"enabled": True, "backend": "codex_cli", "command": "codex", "max_workers": 2}},
        "scheduler": {"max_concurrent_challenges": 2, "max_active_containers": 2,
                      "policy": "local_safe", "fairness": "challenge_round_robin"},
        "worker_policy": {"max_workers_total": 2, "max_workers_per_challenge": 2,
                          "kill_others_on_verified_flag": True},
        # These are deliberately coordinator-local timers.
        "coordinator": {"hint_after_sec": 600, "loop_check_sec": 120},
        "model_routing": {"enabled": False, "config_path": "config/model-routing.yaml"},
        "solver": {"tactical_engine": {"enabled": True, "strategy_registry": "default",
                    "semantic_replanning": True, "semantic_loop_detection": True,
                    "subtype_planners": True, "capability_preflight": True,
                    "legacy_fallback": True}},
        "sandbox": {"enabled": True, "image": "ctf-os-sandbox:latest", "container_per_attempt": True,
                    "precreate_on_queue": False, "max_containers": 2,
                    "command_timeout_sec": 30,
                    "default_limits": {"memory": "16g", "cpus": 2.0}},
        "flag_verification": {"auto_confirm_flags": False, "require_verifier_before_solved": True,
                              "ignore_placeholders": True},
        "watcher": {"poll_interval_sec": 2},
    }


@dataclass(frozen=True)
class AppConfig:
    """Validated local-node configuration.

    All filesystem paths are resolved from the directory containing the config,
    never from the caller's current working directory.  This makes CLI use from
    another directory predictable and keeps state inside the chosen workspace.
    """

    raw: dict[str, Any]
    path: Path

    @classmethod
    def from_file(cls, path: str | Path) -> "AppConfig":
        config_path = Path(path).expanduser().resolve(strict=False)
        result = cls(raw=load_yaml(config_path), path=config_path)
        result.validate()
        return result

    @property
    def root(self) -> Path:
        return self.path.parent

    def get_mapping(self, key: str) -> dict[str, Any]:
        value = self.raw.get(key, {})
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ConfigError(f"{key} must be a mapping")
        return value

    def resolve_path(self, value: str | Path, *, field: str) -> Path:
        if not isinstance(value, (str, Path)) or not str(value).strip():
            raise ConfigError(f"{field} must be a non-empty path")
        candidate = Path(value).expanduser()
        return (candidate if candidate.is_absolute() else self.root / candidate).resolve(strict=False)

    @property
    def mode(self) -> str:
        return str(self.raw["mode"])

    @property
    def solver_mode(self) -> str:
        return str(self.raw.get("solver_mode", "cli_attempt_race"))

    @property
    def contest_name(self) -> str:
        return str(self.get_mapping("contest")["name"])

    @property
    def team_id(self) -> str:
        return str(self.get_mapping("contest")["team_id"])

    @property
    def flag_patterns(self) -> tuple[str, ...]:
        values = self.get_mapping("contest").get("flag_patterns", ())
        if isinstance(values, str):
            values = (values,)
        return tuple(str(value) for value in values)

    @property
    def member_name(self) -> str:
        return str(self.get_mapping("member")["name"])

    @property
    def member_display_name(self) -> str:
        return str(self.get_mapping("member").get("display_name", self.member_name))

    @property
    def owned_categories(self) -> tuple[str, ...]:
        return tuple(str(value).strip().casefold() for value in self.get_mapping("member")["owned_categories"])

    @property
    def incoming_root(self) -> Path:
        return self.resolve_path(self.get_mapping("paths").get("incoming", "incoming"), field="paths.incoming")

    @property
    def output_root(self) -> Path:
        return self.resolve_path(self.get_mapping("paths").get("output", "output"), field="paths.output")

    def incoming_contest_dir(self, contest: str | None = None) -> Path:
        return self.incoming_root / _safe_component(contest or self.contest_name, "contest.name")

    def output_contest_dir(self, contest: str | None = None) -> Path:
        return self.output_root / _safe_component(contest or self.contest_name, "contest.name")

    def workspace_dir(self, contest: str, challenge_slug: str) -> Path:
        return self.incoming_contest_dir(contest) / "workspace" / _safe_component(challenge_slug, "challenge.slug")

    def state_path(self, contest: str | None = None) -> Path:
        return self.output_contest_dir(contest) / "local_state.db"

    @property
    def codex_config(self) -> dict[str, Any]:
        return self.get_mapping("solvers").get("codex", {})

    @property
    def codex_command(self) -> str:
        return str(self.codex_config.get("command", "codex"))

    @property
    def worker_policy(self) -> dict[str, Any]:
        policy = self.get_mapping("worker_policy")
        if policy:
            return policy
        return {"max_workers_total": self.codex_config.get("max_workers", 1), "max_workers_per_challenge": 3}

    @property
    def max_workers_total(self) -> int:
        return int(self.worker_policy.get("max_workers_total", self.codex_config.get("max_workers", 1)))

    @property
    def max_workers_per_challenge(self) -> int:
        return int(self.worker_policy.get("max_workers_per_challenge", 2))

    @property
    def scheduler(self) -> dict[str, Any]:
        return self.get_mapping("scheduler")

    @property
    def max_concurrent_challenges(self) -> int:
        return int(os.environ.get("CTF_OS_MAX_CONCURRENT_CHALLENGES",
                                  self.scheduler.get("max_concurrent_challenges", 2)))

    @property
    def max_active_containers(self) -> int:
        return int(os.environ.get("CTF_OS_MAX_ACTIVE_CONTAINERS",
                                  self.scheduler.get("max_active_containers", self.sandbox.get("max_containers", 2))))

    @property
    def lease_ttl_sec(self) -> float:
        return float(self.worker_policy.get("lease_ttl_sec", 30))

    @property
    def lease_heartbeat_sec(self) -> float:
        return float(self.worker_policy.get("lease_heartbeat_sec", min(10, self.lease_ttl_sec / 2)))

    @property
    def cooldown_on_rate_limit_sec(self) -> float:
        return float(self.worker_policy.get("cooldown_on_rate_limit_sec", 120))

    def attempt_timeout_sec(self, profile: str, default: int) -> int:
        values = self.worker_policy.get("attempt_timeouts", {})
        if not isinstance(values, Mapping):
            raise ConfigError("worker_policy.attempt_timeouts must be a mapping")
        value = values.get(profile, default)
        return _positive_int(value, f"worker_policy.attempt_timeouts.{profile}")

    @property
    def sandbox(self) -> dict[str, Any]:
        return self.get_mapping("sandbox")

    @property
    def sandbox_enabled(self) -> bool:
        return bool(self.sandbox.get("enabled", False))

    @property
    def sandbox_image(self) -> str:
        return os.environ.get("CTF_OS_SANDBOX_IMAGE", str(self.sandbox.get("image", "ctf-os-sandbox:latest")))

    def strategy_image(self, profile: str, declared_image: str) -> str:
        """Resolve an optional profile image, retaining the legacy image by default."""
        images = self.sandbox.get("profile_images", {})
        if not isinstance(images, Mapping):
            raise ConfigError("sandbox.profile_images must be a mapping")
        value = images.get(profile, self.sandbox_image)
        return _required_text(value, f"sandbox.profile_images.{profile}")

    @property
    def tactical_engine(self) -> dict[str, Any]:
        solver = self.get_mapping("solver")
        value = solver.get("tactical_engine", {})
        if not isinstance(value, dict):
            raise ConfigError("solver.tactical_engine must be a mapping")
        return value

    @property
    def tactical_engine_enabled(self) -> bool:
        return bool(self.tactical_engine.get("enabled", True))

    @property
    def sandbox_max_containers(self) -> int:
        return min(int(self.sandbox.get("max_containers", 2)), self.max_active_containers)

    @property
    def sandbox_limits(self) -> tuple[str, float | str]:
        limits = self.sandbox.get("default_limits", {})
        if not isinstance(limits, dict):
            raise ConfigError("sandbox.default_limits must be a mapping")
        return (os.environ.get("CTF_OS_SANDBOX_MEMORY", str(limits.get("memory", "16g"))),
                os.environ.get("CTF_OS_SANDBOX_CPUS", limits.get("cpus", 2.0)))

    @property
    def sandbox_command_timeout_sec(self) -> float:
        return float(self.sandbox.get("command_timeout_sec", 30))

    @property
    def sandbox_egress_policy(self) -> str:
        return str(self.sandbox.get("egress_policy", "manifest_exact_endpoints"))

    @property
    def sandbox_allow_private_egress(self) -> bool:
        """Private egress is permanently disabled without a real mediator."""
        return False

    @property
    def model_routing(self) -> dict[str, Any]:
        return self.get_mapping("model_routing")

    @property
    def model_routing_enabled(self) -> bool:
        return bool(self.model_routing.get("enabled", True))

    @property
    def model_routing_path(self) -> Path:
        return self.resolve_path(self.model_routing.get("config_path", "config/model-routing.yaml"), field="model_routing.config_path")

    @property
    def auto_confirm_flags(self) -> bool:
        return bool(self.get_mapping("flag_verification").get("auto_confirm_flags", False))

    @property
    def require_verifier_before_solved(self) -> bool:
        return bool(self.get_mapping("flag_verification").get("require_verifier_before_solved", True))

    @property
    def ignore_placeholder_flags(self) -> bool:
        return bool(self.get_mapping("flag_verification").get("ignore_placeholders", True))

    @property
    def sandbox_cleanup(self) -> bool:
        return bool(self.sandbox.get("cleanup", True))

    @property
    def preserve_failed_attempts(self) -> bool:
        return bool(self.sandbox.get("preserve_failed_attempts", False))

    @property
    def supervision(self) -> dict[str, Any]:
        """Return the local supervisor timing section.

        ``coordinator`` is the requirements-facing name.  ``supervision`` is
        accepted for the existing example configuration; explicit values in
        it take precedence so an upgrade does not silently change an
        operator's timing policy.
        """
        coordinator = self.get_mapping("coordinator")
        legacy = self.get_mapping("supervision")
        return {**coordinator, **legacy}

    @property
    def hint_after_sec(self) -> float:
        return _positive_number(self.supervision.get("hint_after_sec", 600), "coordinator.hint_after_sec")

    @property
    def loop_check_sec(self) -> float:
        return _positive_number(self.supervision.get("loop_check_sec", 120), "coordinator.loop_check_sec")

    @property
    def supervisor_hint_timeout_sec(self) -> float:
        """Hard bound for one local supervisor request.

        It is kept separate from normal race-attempt timeouts so a stalled
        review cannot become a long-lived coordinator loop.
        """
        return _positive_number(self.supervision.get("hint_timeout_sec", 90), "coordinator.hint_timeout_sec")

    @property
    def knowledge_root(self) -> Path:
        return self.resolve_path(self.get_mapping("knowledge").get("root", "knowledge"), field="knowledge.root")

    @property
    def knowledge_top_k(self) -> int:
        return _positive_int(self.get_mapping("knowledge").get("top_k", 3), "knowledge.top_k")

    @property
    def poll_interval_sec(self) -> float:
        return float(self.get_mapping("watcher").get("poll_interval_sec", 2))

    def model_router(self):
        if not self.model_routing_enabled:
            raise ConfigError("model routing is disabled; enable model_routing before a non-mock run")
        from .model_routing import ModelRouter

        return ModelRouter.from_file(self.model_routing_path)

    def validate(self) -> None:
        if self.raw.get("mode") != "local_node":
            raise ConfigError("mode must be 'local_node'; central and remote execution are unsupported")
        if self.raw.get("solver_mode", "cli_attempt_race") != "cli_attempt_race":
            raise ConfigError("solver_mode must be 'cli_attempt_race'")

        contest = self.get_mapping("contest")
        member = self.get_mapping("member")
        for mapping, key, label in ((contest, "name", "contest.name"), (contest, "team_id", "contest.team_id"),
                                    (member, "name", "member.name")):
            _safe_component(_required_text(mapping.get(key), label), label)
        categories = member.get("owned_categories")
        if not isinstance(categories, list) or not categories or any(not isinstance(item, str) or not item.strip() for item in categories):
            raise ConfigError("member.owned_categories must be a non-empty list of category names")

        patterns = contest.get("flag_patterns", [])
        if patterns is not None and (not isinstance(patterns, list) or any(not isinstance(item, str) or not item for item in patterns)):
            raise ConfigError("contest.flag_patterns must be a list of non-empty strings")

        paths = self.get_mapping("paths")
        for key in ("incoming", "output"):
            if key in paths:
                self.resolve_path(paths[key], field=f"paths.{key}")
        output = self.output_root
        expected_suffix = (self.team_id, self.member_name)
        if len(output.parts) < 2 or output.parts[-2:] != expected_suffix:
            expected = Path("output") / self.team_id / self.member_name
            raise ConfigError(
                f"paths.output must end with {self.team_id!r}/{self.member_name!r} "
                f"to isolate this local node; got {str(output)!r}. Set paths.output "
                f"to {str(expected)!r} (or another base with the same suffix). "
                "Do not delete or move the existing output; use a new local config "
                "for a different team or member."
            )

        codex = self.get_mapping("solvers").get("codex", {})
        if not isinstance(codex, Mapping):
            raise ConfigError("solvers.codex must be a mapping")
        if codex and codex.get("backend", "codex_cli") != "codex_cli":
            raise ConfigError("solvers.codex.backend must be 'codex_cli'")
        _positive_int(self.max_workers_total, "worker_policy.max_workers_total")
        _positive_int(self.max_workers_per_challenge, "worker_policy.max_workers_per_challenge")
        _positive_int(self.max_concurrent_challenges, "scheduler.max_concurrent_challenges")
        _positive_int(self.max_active_containers, "scheduler.max_active_containers")
        if self.lease_ttl_sec <= 0 or self.lease_heartbeat_sec <= 0 or self.lease_heartbeat_sec > self.lease_ttl_sec:
            raise ConfigError("worker_policy lease heartbeat must be positive and no greater than lease_ttl_sec")
        if self.cooldown_on_rate_limit_sec <= 0:
            raise ConfigError("worker_policy.cooldown_on_rate_limit_sec must be positive")
        # Accessing these properties performs type/range validation and keeps
        # their defaults explicit for configs created before supervision.
        _ = (self.hint_after_sec, self.loop_check_sec, self.supervisor_hint_timeout_sec)
        if self.knowledge_top_k < 1 or self.knowledge_top_k > 10:
            raise ConfigError("knowledge.top_k must be an integer in 1..10")
        timeouts = self.worker_policy.get("attempt_timeouts", {})
        if not isinstance(timeouts, Mapping):
            raise ConfigError("worker_policy.attempt_timeouts must be a mapping")
        for profile, timeout in timeouts.items():
            _positive_int(timeout, f"worker_policy.attempt_timeouts.{profile}")

        sandbox = self.sandbox
        if sandbox:
            if not isinstance(sandbox.get("enabled", False), bool):
                raise ConfigError("sandbox.enabled must be a boolean")
            if sandbox.get("enabled", False):
                _required_text(sandbox.get("image", "ctf-os-sandbox:latest"), "sandbox.image")
                _positive_int(self.sandbox_max_containers, "sandbox.max_containers")
                memory, cpus = self.sandbox_limits
                _required_text(memory, "sandbox.default_limits.memory")
                try:
                    if not math.isfinite(float(cpus)) or float(cpus) <= 0:
                        raise ValueError
                except (TypeError, ValueError) as exc:
                    raise ConfigError("sandbox.default_limits.cpus must be positive") from exc
                if self.sandbox_command_timeout_sec <= 0:
                    raise ConfigError("sandbox.command_timeout_sec must be positive")
                if self.sandbox_egress_policy != "manifest_exact_endpoints":
                    raise ConfigError("sandbox.egress_policy must be 'manifest_exact_endpoints'")
                if sandbox.get("allow_private_egress", False):
                    raise ConfigError("sandbox.allow_private_egress is disabled: private, Docker-gateway, and host-service egress are unsafe")
                profile_images = sandbox.get("profile_images", {})
                if not isinstance(profile_images, Mapping):
                    raise ConfigError("sandbox.profile_images must be a mapping")
                for profile, image in profile_images.items():
                    _required_text(image, f"sandbox.profile_images.{profile}")

        tactical = self.tactical_engine
        for field in ("enabled", "semantic_replanning", "semantic_loop_detection",
                      "subtype_planners", "capability_preflight", "legacy_fallback"):
            if field in tactical and not isinstance(tactical[field], bool):
                raise ConfigError(f"solver.tactical_engine.{field} must be a boolean")

        routing = self.model_routing
        if routing and not isinstance(routing.get("enabled", True), bool):
            raise ConfigError("model_routing.enabled must be a boolean")
        if self.model_routing_enabled:
            # Import lazily to avoid a module import cycle; this validates the
            # routing file and its profile references at normal config load time.
            self.model_router()
        verification = self.get_mapping("flag_verification")
        for field in ("auto_confirm_flags", "require_verifier_before_solved", "ignore_placeholders"):
            if field in verification and not isinstance(verification[field], bool):
                raise ConfigError(f"flag_verification.{field} must be a boolean")
        if self.poll_interval_sec <= 0:
            raise ConfigError("watcher.poll_interval_sec must be positive")


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{field} must be a non-empty string")
    return value.strip()


def _safe_component(value: str, field: str) -> str:
    if not value or value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value:
        raise ConfigError(f"{field} is not a safe filesystem component")
    return value


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ConfigError(f"{field} must be a positive integer")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field} must be a positive integer") from exc
    if number < 1:
        raise ConfigError(f"{field} must be a positive integer")
    return number


def _positive_number(value: Any, field: str) -> float:
    if isinstance(value, bool):
        raise ConfigError(f"{field} must be a positive number")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field} must be a positive number") from exc
    if not math.isfinite(number) or number <= 0:
        raise ConfigError(f"{field} must be a positive number")
    return number
