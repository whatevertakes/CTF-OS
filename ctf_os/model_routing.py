from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .config import ConfigError, load_yaml


ALLOWED_REASONING_EFFORTS = frozenset({"medium", "high", "xhigh"})
ALLOWED_MODELS = frozenset({"gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.5"})
ALLOWED_COOLDOWN_SCOPES = frozenset({"selection", "model"})


class ModelRoutingError(ConfigError):
    """Raised when a requested model route is absent or unsafe to infer."""


@dataclass(frozen=True)
class ModelSelection:
    role: str
    profile: str
    model: str
    reasoning_effort: str
    fallback_model: str | None = None
    cooldown_scope: str = "selection"
    # Legacy routing files could name only a raw GPT-5.5 fallback.  It is a
    # terminal, explicit selection rather than an implicit route to the
    # source profile again.
    legacy_fallback: bool = False

    @property
    def cooldown_key(self) -> str:
        """Stable cooldown identity for this exact configured selection."""
        if self.cooldown_scope == "model":
            return f"model:{self.model}"
        return f"selection:{self.profile}:{self.model}:{self.reasoning_effort}"


@dataclass(frozen=True)
class ModelProfile:
    name: str
    model: str
    reasoning_effort: str
    fallbacks: tuple[str, ...] = ()
    fallback_reasoning_effort: str | None = None
    use_for: tuple[str, ...] = ()
    cooldown_scope: str = "selection"

    @property
    def fallback(self) -> str | None:
        """Compatibility accessor for callers of the original one-hop API."""
        return self.fallbacks[0] if self.fallbacks else None


class ModelRouter:
    """Resolve explicit CTF-OS worker routes and bounded fallback sequences."""

    def __init__(
        self,
        profiles: dict[str, ModelProfile],
        default_roles: dict[str, str],
        model_policy: dict[str, dict[str, str]],
        worker_policy: dict[str, Any] | None = None,
    ) -> None:
        self._profiles = profiles
        self._default_roles = default_roles
        self._model_policy = model_policy
        self._worker_policy = dict(worker_policy or {})

    @classmethod
    def from_file(cls, path: str | Path) -> "ModelRouter":
        raw = load_yaml(path)
        return cls.from_mapping(raw)

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> "ModelRouter":
        profiles_raw = raw.get("model_profiles")
        if not isinstance(profiles_raw, dict) or not profiles_raw:
            raise ConfigError("model_profiles must be a non-empty mapping")

        profiles: dict[str, ModelProfile] = {}
        for name, item in profiles_raw.items():
            if not isinstance(item, dict):
                raise ConfigError(f"model_profiles.{name} must be a mapping")
            profile_name = str(name)
            model = _required_str(item, "model", f"model_profiles.{profile_name}")
            _validate_model(model, f"model_profiles.{profile_name}.model")
            effort = item.get("reasoning_effort", "high")
            _validate_effort(effort, f"model_profiles.{profile_name}.reasoning_effort")
            fallback_effort = item.get("fallback_reasoning_effort")
            if fallback_effort is not None:
                _validate_effort(
                    fallback_effort,
                    f"model_profiles.{profile_name}.fallback_reasoning_effort",
                )
            use_for = item.get("use_for", ())
            if not isinstance(use_for, Iterable) or isinstance(use_for, (str, bytes)):
                raise ConfigError(f"model_profiles.{profile_name}.use_for must be a list")
            cooldown_scope = item.get("cooldown_scope", "selection")
            if cooldown_scope not in ALLOWED_COOLDOWN_SCOPES:
                allowed = ", ".join(sorted(ALLOWED_COOLDOWN_SCOPES))
                raise ConfigError(
                    f"model_profiles.{profile_name}.cooldown_scope must be one of: {allowed}"
                )
            profiles[profile_name] = ModelProfile(
                name=profile_name,
                model=model,
                reasoning_effort=str(effort),
                fallbacks=_fallback_targets(item, f"model_profiles.{profile_name}"),
                fallback_reasoning_effort=(
                    str(fallback_effort) if fallback_effort is not None else None
                ),
                use_for=tuple(str(v) for v in use_for),
                cooldown_scope=str(cooldown_scope),
            )

        default_roles = _string_mapping(raw.get("default_roles", {}), "default_roles")
        model_policy_raw = raw.get("model_policy", {})
        if model_policy_raw is None:
            model_policy_raw = {}
        if not isinstance(model_policy_raw, dict):
            raise ConfigError("model_policy must be a mapping")
        model_policy = {
            str(level): _string_mapping(policy, f"model_policy.{level}")
            for level, policy in model_policy_raw.items()
        }
        worker_policy = raw.get("worker_policy", {})
        if worker_policy is None:
            worker_policy = {}
        if not isinstance(worker_policy, dict):
            raise ConfigError("worker_policy must be a mapping")

        router = cls(
            profiles=profiles,
            default_roles=default_roles,
            model_policy=model_policy,
            worker_policy=worker_policy,
        )
        router.validate()
        return router

    def validate(self) -> None:
        for role, profile in self._default_roles.items():
            self._require_profile(profile, f"default_roles.{role}")
        for difficulty, policy in self._model_policy.items():
            for attempt_kind, profile in policy.items():
                self._require_profile(profile, f"model_policy.{difficulty}.{attempt_kind}")
        for profile in self._profiles.values():
            for fallback in profile.fallbacks:
                self._validate_fallback_target(profile, fallback)
        self._validate_fallback_graph()
        self._validate_worker_policy()
        self._validate_runtime_matrix()

    def _validate_fallback_target(self, profile: ModelProfile, fallback: str) -> None:
        if fallback in self._profiles:
            if profile.fallback_reasoning_effort is not None:
                raise ConfigError(
                    f"model_profiles.{profile.name}.fallback_reasoning_effort is only valid "
                    "with a legacy raw GPT-5.5 fallback; use the target profile effort instead"
                )
            return
        # Retain compatibility with the original ``fallback: gpt-5.5`` form.
        # Other raw models were never permitted as fallbacks, because that
        # would bypass the configured role/profile policy.
        if fallback != "gpt-5.5":
            raise ConfigError(
                f"model_profiles.{profile.name}.fallback must reference a configured profile "
                "or the legacy supported GPT-5.5 fallback model"
            )

    def _validate_fallback_graph(self) -> None:
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(name: str) -> None:
            if name in visiting:
                raise ConfigError(f"model fallback cycle detected at profile: {name}")
            if name in visited:
                return
            visiting.add(name)
            profile = self._profiles[name]
            for target in profile.fallbacks:
                if target in self._profiles:
                    visit(target)
            visiting.remove(name)
            visited.add(name)

        for name in self._profiles:
            visit(name)

    def _validate_worker_policy(self) -> None:
        threshold = self._worker_policy.get("promote_to_sol_after_failures", 0)
        if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 0:
            raise ConfigError("worker_policy.promote_to_sol_after_failures must be a non-negative integer")
        promotion = self._worker_policy.get("promotion_profile")
        if threshold:
            if not isinstance(promotion, str) or not promotion:
                raise ConfigError(
                    "worker_policy.promotion_profile must name an explicit Sol supervisor/review profile "
                    "when promote_to_sol_after_failures is enabled"
                )
            self._require_profile(promotion, "worker_policy.promotion_profile")
            profile = self._profiles[promotion]
            if profile.model != "gpt-5.6-sol":
                raise ConfigError("worker_policy.promotion_profile must use gpt-5.6-sol")
        quota_stop = self._worker_policy.get("stop_new_workers_on_quota_warning", False)
        if not isinstance(quota_stop, bool):
            raise ConfigError("worker_policy.stop_new_workers_on_quota_warning must be a boolean")

    def _validate_runtime_matrix(self) -> None:
        """Reject a config that would only fail after a challenge is queued."""
        # Import lazily to keep this module independent from solver backends.
        from .solver_engine.race_plan import RacePlan

        scores = {"easy": 0, "medium": 201, "hard": 500}
        for difficulty, score in scores.items():
            policy = self._model_policy.get(difficulty, {})
            for race_attempt in RacePlan.for_score(score).attempts:
                profile = race_attempt.profile
                if profile.name in policy:
                    continue
                if profile.role in self._default_roles or profile.name in self._default_roles:
                    continue
                raise ModelRoutingError(
                    f"missing explicit route for runtime attempt {difficulty}.{profile.name}; "
                    f"configure model_policy.{difficulty}.{profile.name} or default_roles.{profile.role}"
                )

    @property
    def promote_to_sol_after_failures(self) -> int:
        return int(self._worker_policy.get("promote_to_sol_after_failures", 0))

    @property
    def stop_new_workers_on_quota_warning(self) -> bool:
        return bool(self._worker_policy.get("stop_new_workers_on_quota_warning", False))

    def select_promotion(self, *, role: str = "supervisor") -> ModelSelection:
        profile = self._worker_policy.get("promotion_profile")
        if not isinstance(profile, str) or not profile:
            raise ModelRoutingError("no explicit worker_policy.promotion_profile is configured")
        self._require_profile(profile, "worker_policy.promotion_profile")
        return self._selection_from_profile(profile, role=role)

    def select(
        self,
        *,
        role: str | None = None,
        difficulty: str | None = None,
        attempt_kind: str | None = None,
    ) -> ModelSelection:
        profile_name = self._resolve_profile_name(
            role=role,
            difficulty=difficulty,
            attempt_kind=attempt_kind,
        )
        return self._selection_from_profile(profile_name, role=role or attempt_kind or "default")

    def select_fallback(self, selection: ModelSelection) -> ModelSelection:
        """Return the first configured fallback, or the original selection if absent."""
        fallbacks = self._fallback_selections(selection)
        return fallbacks[0] if fallbacks else selection

    def selection_sequence(self, selection: ModelSelection) -> tuple[ModelSelection, ...]:
        """Return a finite, ordered sequence of configured distinct selections.

        The input is always first.  Direct fallbacks are considered in their
        YAML order, then their explicitly configured descendants.  Validation
        rejects profile cycles; the key set remains a defensive bound for old
        raw-model fallback configurations and future config extensions.
        """
        pending = [selection]
        result: list[ModelSelection] = []
        seen: set[str] = set()
        while pending:
            current = pending.pop(0)
            if current.cooldown_key in seen:
                continue
            seen.add(current.cooldown_key)
            result.append(current)
            pending.extend(self._fallback_selections(current))
        return tuple(result)

    def _selection_from_profile(self, profile_name: str, *, role: str) -> ModelSelection:
        profile = self._profiles[profile_name]
        fallback = self._fallback_selections_for_profile(profile, role=role)
        return ModelSelection(
            role=role,
            profile=profile.name,
            model=profile.model,
            reasoning_effort=profile.reasoning_effort,
            fallback_model=fallback[0].model if fallback else None,
            cooldown_scope=profile.cooldown_scope,
        )

    def _fallback_selections(self, selection: ModelSelection) -> tuple[ModelSelection, ...]:
        if selection.legacy_fallback:
            return ()
        profile = self._profiles.get(selection.profile)
        if profile is None:
            return ()
        # A legacy raw fallback intentionally reuses the source profile name
        # for display compatibility.  Once selected, it must not restart that
        # source profile's fallback chain.
        if selection.model != profile.model or selection.reasoning_effort != profile.reasoning_effort:
            return ()
        return self._fallback_selections_for_profile(profile, role=selection.role)

    def _fallback_selections_for_profile(
        self, profile: ModelProfile, *, role: str
    ) -> tuple[ModelSelection, ...]:
        result: list[ModelSelection] = []
        for target in profile.fallbacks:
            if target in self._profiles:
                result.append(self._selection_from_profile(target, role=role))
                continue
            # ``_validate_fallback_target`` permits only the legacy GPT-5.5
            # raw fallback.  Its key includes the source profile/effort so it
            # cannot accidentally cool every GPT-5.5 selection globally.
            result.append(ModelSelection(
                role=role,
                profile=profile.name,
                model=target,
                reasoning_effort=profile.fallback_reasoning_effort or profile.reasoning_effort,
                fallback_model=None,
                cooldown_scope=profile.cooldown_scope,
                legacy_fallback=True,
            ))
        return tuple(result)

    def _resolve_profile_name(
        self,
        *,
        role: str | None,
        difficulty: str | None,
        attempt_kind: str | None,
    ) -> str:
        if difficulty and attempt_kind:
            policy = self._model_policy.get(difficulty)
            if policy and attempt_kind in policy:
                return policy[attempt_kind]

        if role and role in self._default_roles:
            return self._default_roles[role]

        if attempt_kind and attempt_kind in self._default_roles:
            return self._default_roles[attempt_kind]

        if not role and not difficulty and not attempt_kind and "default" in self._default_roles:
            return self._default_roles["default"]

        requested = ", ".join(
            f"{name}={value!r}"
            for name, value in (("role", role), ("difficulty", difficulty), ("attempt_kind", attempt_kind))
            if value
        ) or "no route selectors"
        raise ModelRoutingError(
            f"no explicit model route for {requested}; configure an exact model_policy route "
            "or a matching default_roles entry"
        )

    def _require_profile(self, profile: str, field: str) -> None:
        if profile not in self._profiles:
            raise ConfigError(f"{field} references unknown model profile: {profile}")


def _required_str(item: dict[str, Any], key: str, prefix: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{prefix}.{key} must be a non-empty string")
    return value


def _fallback_targets(item: dict[str, Any], prefix: str) -> tuple[str, ...]:
    has_single = "fallback" in item and item.get("fallback") is not None
    has_many = "fallbacks" in item and item.get("fallbacks") is not None
    if has_single and has_many:
        raise ConfigError(f"{prefix} may set either fallback or fallbacks, not both")
    if has_single:
        value = _optional_str(item, "fallback", prefix)
        return (value,) if value else ()
    if not has_many:
        return ()
    value = item.get("fallbacks")
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
        raise ConfigError(f"{prefix}.fallbacks must be a list of non-empty strings")
    targets = tuple(str(target) for target in value)
    if not targets or any(not target for target in targets):
        raise ConfigError(f"{prefix}.fallbacks must be a non-empty list of non-empty strings")
    if len(set(targets)) != len(targets):
        raise ConfigError(f"{prefix}.fallbacks must not contain duplicate selections")
    return targets


def _optional_str(item: dict[str, Any], key: str, prefix: str) -> str | None:
    value = item.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{prefix}.{key} must be a non-empty string when set")
    return value


def _string_mapping(value: Any, name: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a mapping")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(item, str) or not item:
            raise ConfigError(f"{name}.{key} must be a non-empty string")
        result[str(key)] = item
    return result


def _validate_effort(value: Any, field: str) -> None:
    if value not in ALLOWED_REASONING_EFFORTS:
        allowed = ", ".join(sorted(ALLOWED_REASONING_EFFORTS))
        raise ConfigError(f"{field} must be one of: {allowed}")


def _validate_model(value: Any, field: str) -> None:
    if value not in ALLOWED_MODELS:
        allowed = ", ".join(sorted(ALLOWED_MODELS))
        raise ConfigError(f"{field} must be one of: {allowed}")
