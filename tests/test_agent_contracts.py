from pathlib import Path


def test_skills_and_agents_define_sol_native_contract() -> None:
    intake = Path(".codex/skills/ctf-intake/SKILL.md").read_text()
    triage = Path(".codex/skills/ctf-triage/SKILL.md").read_text()
    solve = Path(".codex/skills/ctf-solve/SKILL.md").read_text()
    agents = Path("AGENTS.md").read_text()
    for required in (
        "current user-opened", "spawn_queue", "spawn_agent", 'fork_turns=\"none\"',
        "actual returned native", "independent", "exploit-first", "tool-driven",
        "Root does not wait", "ATTACK_PATH_FOUND", "next two meaningful tool actions",
        "recording failure never blocks execution", "swarm-replace", "90 minutes",
        "flag-found", "interrupt_agent", "automatic submission is forbidden",
        "Whole-contest Intake, Triage",
    ):
        assert required in solve
    assert "--session-input-json" in solve
    assert "optional legacy/admin" in intake
    assert "current user-opened Sol session" in agents
    assert "prepare only that challenge" in agents
    assert "never Solve prerequisites" in agents
    assert "only user-maintained contest input" not in agents
    assert "not a Solve prerequisite" in triage and "triage-finalize" in triage


def test_solve_docs_do_not_require_contest_wide_handoffs() -> None:
    text = "\n".join(
        Path(path).read_text().casefold()
        for path in (
            "AGENTS.md", "README.md", ".codex/skills/ctf-solve/SKILL.md",
            "ctf_os/resources/agent-policy.md",
        )
    )
    for forbidden in (
        "run intake first", "run triage first", "open a new solve session",
        "choose by difficulty",
    ):
        assert forbidden not in text
    assert "intake\n→ triage\n→ board" not in text
    assert "problems.txt" not in Path("README.md").read_text()


def test_removed_engine_contracts_are_absent_from_live_surface() -> None:
    source = Path("ctf_os/agent_tools/__main__.py").read_text()
    for forbidden in (
        "race-plan-start", "branch-admit", "PRIMITIVE_CANDIDATE",
        "PRIMITIVE_CONFIRMED", "working-poc-commit", "control-action",
        "benchmark-start", "fixed-race", "adaptive-race", "sol-only",
    ):
        assert forbidden not in source


def test_runtime_has_no_model_launcher_or_legacy_product_surface() -> None:
    python = "\n".join(path.read_text(errors="ignore") for path in Path("ctf_os").rglob("*.py"))
    forbidden = ("CodexCliBackend", "broker_socket", "owned_categories", "team_id", "member_name", "subprocess.*codex")
    for text in forbidden:
        assert text not in python
    assert not Path("ctf_os/cli.py").exists()
    assert not Path("ctf_os/solver_engine").exists()


def test_runtime_has_no_model_api_client_or_automatic_ctfd_submit() -> None:
    python = "\n".join(path.read_text(errors="ignore").casefold() for path in Path("ctf_os").rglob("*.py"))
    for forbidden in (
        "openai(", "anthropic(", "genai.", "codex exec", "codex app-server",
        "subprocess.run([\"codex\"", "subprocess.run([\"claude\"", "ctfd submit",
    ):
        assert forbidden not in python


def test_competition_docs_preserve_minimum_boundaries() -> None:
    text = (Path("AGENTS.md").read_text() + Path("ctf_os/resources/agent-policy.md").read_text()).casefold()
    for required in (
        "host docker socket", "ssh", "browser", "personal cloud", "cloud metadata",
        "undeclared private", "never submit", "native delegation",
    ):
        assert required in text
