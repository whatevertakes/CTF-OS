from pathlib import Path


def test_skills_and_agents_define_sol_native_contract() -> None:
    intake = Path(".codex/skills/ctf-intake/SKILL.md").read_text()
    triage = Path(".codex/skills/ctf-triage/SKILL.md").read_text()
    solve = Path(".codex/skills/ctf-solve/SKILL.md").read_text()
    agents = Path("AGENTS.md").read_text()
    assert "current user-opened Sol session" in solve
    assert "native delegation" in solve
    assert "Tier 2: three children" in solve
    assert "SUBMISSION_RECOMMENDED" in solve
    assert "Full clean replay: not required" in solve
    assert "Never run Codex" in solve
    assert "solve_launch_context" in solve
    assert "observation-ordering hints only" in solve
    assert "They are not confirmed vulnerabilities or exploit primitives" in solve
    assert "A Triage recommendation, difficulty, or success estimate never substitutes" in solve
    assert "dedicated session" in intake
    assert "keep the current user-opened Sol session" in agents
    assert "repairs missing or stale Intake in the same session" in agents
    assert "no-solve stage" in triage and "triage-finalize" in triage


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
