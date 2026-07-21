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
    assert "Preflight observation hints only" in solve
    assert "They are not confirmed vulnerabilities or exploit primitives" in solve
    assert "challenge-local preflight" in solve
    assert "Whole-contest Intake and Triage are not prerequisites" in solve
    assert "pass that explicit information to the internal prepare call using the existing session input format" in solve
    assert "This is not a separate user step" in solve
    assert "--session-input-json" not in solve
    assert "optional legacy/admin" in intake
    assert "keep the current user-opened Sol session" in agents
    assert "run its internal challenge-local preflight" in agents
    assert "not Solve prerequisites" in agents
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
    readme = Path("README.md").read_text()
    standard_flow = readme.split("표준 사용 흐름은 다음과 같습니다.", 1)[1].split(
        "## Low-level CLI debugging", 1,
    )[0]
    assert "problems.txt" not in standard_flow


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
