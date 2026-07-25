"""Fresh-clone and operator-footgun regression coverage."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import ctf_os.doctor as doctor_module
from ctf_os.agent_tools.__main__ import _lane_json, build_parser
from ctf_os.contest import ContestError, initialize_contest, parse_contest
from ctf_os.doctor import run_doctor
from ctf_os.flag import FlagError, StreamingDetector, valid_candidate
from ctf_os.preflight import input_fingerprint


def _lane_spec() -> dict[str, str]:
    return {
        "model_profile": "sol-xhigh",
        "role": "independent attacker",
        "task": "pursue a distinct parser attack",
        "context_mode": "fresh",
        "attack_family": "parser-differential",
    }


def test_race_prepare_cli_requires_explicit_remote_execution_mode() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["race-prepare", "1", "--contest", "Demo CTF"])

    parsed = parser.parse_args([
        "race-prepare",
        "1",
        "--contest",
        "Demo CTF",
        "--remote-execution",
        "human-relay",
    ])
    assert parsed.remote_execution == "human-relay"


def test_init_contest_blank_flag_pattern_blocks_before_run_creation(
    tmp_path: Path,
) -> None:
    initialized = initialize_contest(tmp_path, "Demo CTF", "web/Example")
    challenge_root = Path(str(initialized["challenge_path"]))
    (challenge_root / "input.txt").write_text("challenge", encoding="utf-8")

    manifest = parse_contest(Path(str(initialized["manifest_path"])))
    challenge = manifest.challenges[0]
    assert challenge.flag_pattern is None
    with pytest.raises(ContestError, match="non-empty flag pattern"):
        input_fingerprint(manifest, challenge)
    assert valid_candidate("CTF{would_be_silent}", None) is False
    with pytest.raises(FlagError, match="non-empty flag pattern"):
        StreamingDetector(None)

    prepared = subprocess.run(
        [
            "python",
            "-m",
            "ctf_os.agent_tools",
            "--repo",
            str(tmp_path),
            "race-prepare",
            "web/Example",
            "--contest",
            "Demo CTF",
            "--remote-execution",
            "human-relay",
            "--dry-run",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert prepared.returncode == 1
    assert "non-empty flag pattern" in prepared.stdout
    assert not (tmp_path / "output").exists()


def test_invalid_flag_pattern_is_rejected_before_fingerprinting(tmp_path: Path) -> None:
    initialized = initialize_contest(tmp_path, "Demo CTF", "web/Example")
    manifest_path = Path(str(initialized["manifest_path"]))
    manifest_path.write_text(
        "# Contest: Demo CTF\n"
        "- flag_pattern: [unterminated\n\n"
        "### web/Example\n"
        "- description: example\n",
        encoding="utf-8",
    )
    (Path(str(initialized["challenge_path"])) / "input.txt").write_text(
        "challenge",
        encoding="utf-8",
    )
    manifest = parse_contest(manifest_path)

    with pytest.raises(ContestError, match="flag pattern is invalid"):
        input_fingerprint(manifest, manifest.challenges[0])


def test_doctor_can_validate_only_the_fresh_clone_profiles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inspected: list[tuple[str, ...]] = []

    def fake_smoke(profiles, *, docker, runner):
        selected = tuple(profiles)
        inspected.append(selected)
        return {
            "profiles": [
                {
                    "image": f"ctf-os-sandbox:{profile}",
                    "available": True,
                }
                for profile in selected
            ],
            "all_available": True,
        }

    def runner(argv, **_kwargs):
        if argv[:2] == ["docker", "info"]:
            return subprocess.CompletedProcess(argv, 0, "linux x86_64\n", "")
        if argv[:3] == ["docker", "compose", "version"]:
            return subprocess.CompletedProcess(argv, 0, "v2.24.0\n", "")
        if argv[0] == "nvidia-smi":
            raise FileNotFoundError("no optional NVIDIA GPU")
        raise AssertionError(argv)

    monkeypatch.setattr(doctor_module, "smoke_images", fake_smoke)
    monkeypatch.setattr(doctor_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(doctor_module.platform, "machine", lambda: "x86_64")

    result = run_doctor(
        tmp_path,
        profiles=("base", "web", "pwn"),
        runner=runner,
    )

    assert result["ok"] is True
    assert result["required_profiles"] == ["base", "web", "pwn"]
    assert result["build_command"] == [
        "sandbox/build-images.sh",
        "base",
        "web",
        "pwn",
    ]
    assert inspected == [("base", "web", "pwn")]


def test_cli_accepts_repeatable_lane_and_case_insensitive_end_reason() -> None:
    parser = build_parser()
    lane = json.dumps(_lane_spec())
    parsed = parser.parse_args([
        "race-bootstrap",
        "1",
        "--contest",
        "Demo CTF",
        "--lane",
        lane,
    ])
    assert _lane_json(parsed) == [_lane_spec()]

    ended = parser.parse_args(["race-end", "--reason", "stopped"])
    assert ended.reason == "STOPPED"


def test_onboarding_contract_is_visible_in_every_operator_surface() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    agents = Path("AGENTS.md").read_text(encoding="utf-8")
    solve_skill = Path(".codex/skills/ctf-solve/SKILL.md").read_text(
        encoding="utf-8"
    )
    claude_skill = Path(
        ".claude/skills/ctf-claude-handoff/SKILL.md"
    ).read_text(encoding="utf-8")
    workflow = Path(".github/workflows/ctf-os-ci.yml").read_text(encoding="utf-8")
    build = Path("sandbox/build-images.sh").read_text(encoding="utf-8")

    assert "--remote-execution human-relay" in readme
    assert "--profiles web pwn rev crypto osint misc ai" in readme
    assert "해석되지 않는 주최측 주소도" in readme
    assert "--remote-execution '<agent|human-relay>'" in agents
    assert "--remote-execution '<agent|human-relay>'" in solve_skill
    assert "../../../.codex/skills/ctf-claude-handoff/SKILL.md" in claude_skill
    assert '      - "**"' in workflow
    assert "doctor --profiles ${PROFILES[*]}" in build
