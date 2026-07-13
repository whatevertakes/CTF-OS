from __future__ import annotations

import json
from pathlib import Path

import yaml

from ctf_os.cli import _build_parser, main
from ctf_os.config import AppConfig, default_config_mapping
from ctf_os.workbench import ManualSolveWorkbench, SolveContext, SolveResult


def _config(tmp_path: Path) -> AppConfig:
    raw = default_config_mapping("Demo")
    raw["member"]["owned_categories"] = ["web"]
    raw["model_routing"]["enabled"] = True
    raw["model_routing"]["config_path"] = str(
        Path(__file__).parents[1] / "config" / "model-routing.yaml"
    )
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    manifest = tmp_path / "incoming" / "Demo" / "contest.md"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        "# 대회명: Demo\n\n### web/login\n- 설명: authorized local challenge\n",
        encoding="utf-8",
    )
    source = manifest.parent / "web" / "login"
    source.mkdir(parents=True)
    (source / "app.py").write_text("print('challenge')\n", encoding="utf-8")
    return AppConfig.from_file(path)


class CompletedRunner:
    def run(self, context: SolveContext) -> SolveResult:
        return SolveResult("COMPLETED", "manual lead finished")


def test_deprecated_run_never_creates_state_or_starts_workers(tmp_path: Path, capsys) -> None:
    config = _config(tmp_path)

    assert main(["run", "--config", str(config.path)]) == 2

    assert "no longer starts a contest-wide scheduler" in capsys.readouterr().err
    assert not config.state_path().exists()
    assert not list(config.output_contest_dir().glob("*/session.json"))


def test_intake_cli_lists_reports_without_starting_a_session(tmp_path: Path, capsys) -> None:
    config = _config(tmp_path)

    assert main(["intake", "--config", str(config.path)]) == 0

    output = capsys.readouterr().out
    assert "READY" in output and "web/login" in output
    assert "no solver started" in output
    assert (config.output_contest_dir() / "briefs" / "web-login" / "intake.md").is_file()
    assert not list(config.output_contest_dir().glob("*/session.json"))
    assert not config.state_path().exists()


def test_tui_and_parse_commands_are_absent() -> None:
    choices = _build_parser()._subparsers._group_actions[0].choices

    assert "tui" not in choices
    assert "parse" not in choices


def test_pause_resume_retry_change_only_manual_session_index(tmp_path: Path) -> None:
    config = _config(tmp_path)
    workbench = ManualSolveWorkbench(config, runner=CompletedRunner())
    workbench.start("login", max_subworkers=0)

    path = workbench.set_state("login", "PAUSED")
    assert json.loads(path.read_text(encoding="utf-8"))["status"] == "PAUSED"
    workbench.set_state("login", "STOPPED")
    assert json.loads(path.read_text(encoding="utf-8"))["status"] == "STOPPED"
    assert not config.state_path().exists()
