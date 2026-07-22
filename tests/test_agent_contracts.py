from pathlib import Path


def test_skills_and_agents_define_dynamic_native_worker_contract() -> None:
    intake = Path(".codex/skills/ctf-intake/SKILL.md").read_text()
    triage = Path(".codex/skills/ctf-triage/SKILL.md").read_text()
    solve = Path(".codex/skills/ctf-solve/SKILL.md").read_text()
    agents = Path("AGENTS.md").read_text()
    for required in (
        "current user-opened", "worker-spawn-packet", "spawn_agent", 'fork_turns="none"',
        "worker-spawn-confirm", "sol-xhigh", "terra-high", "luna-high",
        "Root immediately", "completed command", "logging failure never",
        "worker-replace", "90 minutes", "flag-found", "interrupt_agent",
        "A human submits", "Whole-contest", "sandbox-create", "sandbox-exec",
        "worker_paths.metadata_path", "Direct host execution",
    ):
        assert required in solve
    assert "--session-input-json" in solve
    assert "optional legacy/admin" in intake
    assert "current user-opened Root Sol session" in agents
    assert "prepare only that" in agents
    assert "never Solve prerequisites" in agents
    assert "live `root` sandbox" in agents
    assert "host execution" in agents and "CTF-OS controller commands" in agents
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
        "choose by difficulty", "contest allocator",
    ):
        assert forbidden not in text
    assert "intake\n→ triage\n→ board" not in text
    assert "problems.txt" not in Path("README.md").read_text()


def test_removed_engine_contracts_are_absent_from_live_surface() -> None:
    source = "\n".join(
        Path(path).read_text()
        for path in (
            "ctf_os/agent_tools/__main__.py", "ctf_os/swarm.py", "ctf_os/solve_launch.py",
        )
    )
    for forbidden in (
        "race-plan-start", "branch-admit", "PRIMITIVE_CANDIDATE",
        "PRIMITIVE_CONFIRMED", "working-poc-commit", "control-action",
        "benchmark-start", "fixed-race", "adaptive-race", "sol-only",
        "INITIAL_LANES", "spawn_queue", "initial_child_roles",
        "planned_child_width", "SPAWN_REQUIRED",
    ):
        assert forbidden not in source


def test_live_contract_has_no_fixed_initial_lane_names() -> None:
    text = "\n".join(
        Path(path).read_text()
        for path in (
            "AGENTS.md", "README.md", ".codex/skills/ctf-solve/SKILL.md",
            "ctf_os/resources/agent-policy.md", "ctf_os/swarm.py", "ctf_os/solve_launch.py",
        )
    )
    for forbidden in ("exploit-first", "tool-driven", '"independent"'):
        assert forbidden not in text


def test_required_model_profiles_are_short_and_present() -> None:
    expected = {
        "ctf_sol_xhigh": "gpt-5.6-sol",
        "ctf_terra_high": "gpt-5.6-terra",
        "ctf_luna_high": "gpt-5.6-luna",
        "ctf_sol_max": "gpt-5.6-sol",
    }
    for profile, model in expected.items():
        text = Path(f".codex/agents/{profile}.toml").read_text()
        assert f'name = "{profile}"' in text and f'model = "{model}"' in text
        assert "sandbox-exec" in text
        assert "worker_paths.metadata_path" in text
        assert "directly on the host" in text
        assert len(text.splitlines()) < 24


def test_mandatory_sandbox_flow_is_consistent_across_authoritative_docs() -> None:
    documents = [
        Path(path).read_text()
        for path in (
            "AGENTS.md", "README.md", ".codex/skills/ctf-solve/SKILL.md",
            "ctf_os/resources/agent-policy.md",
        )
    ]
    for text in documents:
        assert "sandbox-create" in text or "creates" in text
        assert "sandbox-exec" in text
        assert "category sandbox" in text
        assert "host" in text
    solve = documents[2]
    assert solve.index("sandbox-create") < solve.index("Root now attacks immediately")
    assert "A worker may be spawned only after that probe succeeds" in solve
    assert "Keep the Root sandbox alive" in solve


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
        "undeclared private", "never submit", "native", "sandbox-exec",
    ):
        assert required in text
