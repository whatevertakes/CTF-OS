from pathlib import Path


def test_skills_and_agents_define_sol_native_contract() -> None:
    intake = Path(".codex/skills/ctf-intake/SKILL.md").read_text()
    triage = Path(".codex/skills/ctf-triage/SKILL.md").read_text()
    solve = Path(".codex/skills/ctf-solve/SKILL.md").read_text()
    agents = Path("AGENTS.md").read_text()
    assert "current user-opened Sol session" in solve
    assert "native delegation" in solve
    assert "three non-overlapping" in solve
    assert "READY_FOR_HUMAN_SUBMISSION" in solve
    assert "Never run Codex" in solve
    assert "dedicated session" in intake and "new session" in agents
    assert "no-solve stage" in triage and "triage-finalize" in triage


def test_runtime_has_no_model_launcher_or_legacy_product_surface() -> None:
    python = "\n".join(path.read_text(errors="ignore") for path in Path("ctf_os").rglob("*.py"))
    forbidden = ("CodexCliBackend", "broker_socket", "owned_categories", "team_id", "member_name", "subprocess.*codex")
    for text in forbidden:
        assert text not in python
    assert not Path("ctf_os/cli.py").exists()
    assert not Path("ctf_os/solver_engine").exists()
