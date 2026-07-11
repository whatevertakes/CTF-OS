from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_os.config import ConfigError, load_yaml
from ctf_os.cli import main
from ctf_os.model_routing import ModelRouter, ModelRoutingError
from ctf_os.solver_engine.codex_cli_backend import CodexCliBackend, CodexExecRequest
from ctf_os.solver_engine.race_plan import RacePlan


ROUTING_CONFIG = Path("config/model-routing.yaml")
PACKAGED_ROUTING_CONFIG = Path("ctf_os/resources/model-routing.yaml")


def test_default_role_routes_to_sol_xhigh() -> None:
    router = ModelRouter.from_file(ROUTING_CONFIG)

    selection = router.select(role="architect")

    assert selection.profile == "sol_xhigh"
    assert selection.model == "gpt-5.6-sol"
    assert selection.reasoning_effort == "max"
    assert selection.fallback_model == "gpt-5.5"


def test_easy_recon_routes_to_luna_high() -> None:
    router = ModelRouter.from_file(ROUTING_CONFIG)

    selection = router.select(difficulty="easy", attempt_kind="recon_fast")

    assert selection.profile == "luna_high"
    assert selection.model == "gpt-5.6-luna"
    assert selection.reasoning_effort == "high"


def test_hard_exploit_main_routes_to_sol_max() -> None:
    router = ModelRouter.from_file(ROUTING_CONFIG)

    selection = router.select(difficulty="hard", attempt_kind="exploit_main")

    assert selection.profile == "sol_xhigh"
    assert selection.model == "gpt-5.6-sol"
    assert selection.reasoning_effort == "max"


def test_fallback_preserves_configured_effort() -> None:
    router = ModelRouter.from_file(ROUTING_CONFIG)
    selection = router.select(role="architect")

    fallback = router.select_fallback(selection)

    assert fallback.model == "gpt-5.5"
    assert fallback.profile == "gpt55_xhigh"
    assert fallback.reasoning_effort == "xhigh"
    assert fallback.fallback_model is None


def test_rejects_unknown_reasoning_effort() -> None:
    with pytest.raises(ConfigError):
        ModelRouter.from_mapping(
            {
                "model_profiles": {
                    "bad": {
                        "model": "gpt-5.6-sol",
                        "reasoning_effort": "extreme",
                    }
                }
            }
        )


def test_rejects_unapproved_model_names() -> None:
    with pytest.raises(ConfigError, match="model_profiles.bad.model"):
        ModelRouter.from_mapping({"model_profiles": {"bad": {"model": "not-a-codex-model", "reasoning_effort": "high"}}})
    with pytest.raises(ConfigError, match="fallback"):
        ModelRouter.from_mapping({"model_profiles": {"bad": {"model": "gpt-5.6-terra", "reasoning_effort": "high", "fallback": "gpt-5.6-sol"}}})


def test_codex_exec_argv_contains_model_and_reasoning(sterile_staging_factory) -> None:
    router = ModelRouter.from_file(ROUTING_CONFIG)
    backend = CodexCliBackend(model_router=router)
    staging = sterile_staging_factory()
    socket_path = staging.workdir / ".ctf-os-broker"
    socket_path.mkdir(mode=0o700)

    argv = backend.build_exec_argv(
        CodexExecRequest(
            workdir=staging.workdir,
            prompt="solve this",
            difficulty="hard",
            attempt_kind="exploit_alt",
            broker_socket=socket_path,
        )
    )

    assert argv[:9] == [
        "codex",
        "exec",
        "--strict-config",
        "--ignore-user-config",
        "--ignore-rules",
        "--ephemeral",
        "--disable",
        "hooks",
        "--skip-git-repo-check",
    ]
    assert "--sandbox" not in argv
    assert argv[argv.index("-C") : argv.index("-C") + 4] == [
        "-C",
        str(staging.workdir),
        "-m",
        "gpt-5.6-terra",
    ]
    assert 'model_reasoning_effort="max"' in argv
    assert "--dangerously-bypass-approvals-and-sandbox" not in argv
    assert 'approval_policy="never"' in argv
    assert 'default_permissions="ctf_os_attempt"' in argv
    profile = next(item for item in argv if item.startswith("permissions.ctf_os_attempt="))
    assert "network={enabled=false" in profile
    assert "unix_sockets" not in profile
    assert argv[-1] == "solve this"


def test_cli_model_route_json(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(
        [
            "model-route",
            "--routing-config",
            str(ROUTING_CONFIG),
            "--difficulty",
            "medium",
            "--attempt-kind",
            "recon_deep",
            "--json",
        ]
    )

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["model"] == "gpt-5.6-terra"
    assert payload["reasoning_effort"] == "high"


def test_shipped_routing_graph_reaches_every_profile_through_runtime_and_public_selectors() -> None:
    router = ModelRouter.from_file(ROUTING_CONFIG)
    raw = load_yaml(ROUTING_CONFIG)
    assert ROUTING_CONFIG.read_bytes() == PACKAGED_ROUTING_CONFIG.read_bytes()
    roots = [
        router.select(role=role)
        for role in raw["default_roles"]
    ]
    roots.extend(
        router.select(difficulty=difficulty, attempt_kind=attempt_kind)
        for difficulty, policy in raw["model_policy"].items()
        for attempt_kind in policy
    )
    roots.extend(
        router.select(
            role=race_attempt.profile.role,
            difficulty=difficulty,
            attempt_kind=race_attempt.profile.name,
        )
        for difficulty, score in {"easy": 0, "medium": 201, "hard": 500}.items()
        for race_attempt in RacePlan.for_score(score).attempts
    )
    roots.append(router.select_promotion())

    sequences = [router.selection_sequence(root) for root in roots]
    assert all(len(sequence) == len({item.cooldown_key for item in sequence}) for sequence in sequences)
    assert all(len(sequence) <= len(raw["model_profiles"]) for sequence in sequences)

    reachable_profiles = {item.profile for sequence in sequences for item in sequence}
    assert reachable_profiles == set(raw["model_profiles"])

    fallback_efforts = {
        item.reasoning_effort
        for sequence in sequences
        for item in sequence[1:]
        if item.model == "gpt-5.5"
    }
    assert fallback_efforts == {"medium", "high", "xhigh"}


def test_missing_route_fails_closed_without_implicit_profile_or_implementer() -> None:
    with pytest.raises(ModelRoutingError, match="missing explicit route for runtime attempt hard.source_deep"):
        ModelRouter.from_mapping(
            {
                "model_profiles": {"only": {"model": "gpt-5.6-terra", "reasoning_effort": "high"}},
                "default_roles": {"recon": "only", "exploit": "only"},
                "model_policy": {"easy": {"recon_fast": "only", "exploit_fast": "only"}},
            }
        )
