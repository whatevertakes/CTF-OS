from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from threading import Event as ThreadEvent, Thread

import pytest
import yaml

from ctf_os.cli import _build_parser
from ctf_os.config import AppConfig, default_config_mapping
from ctf_os.workbench import (
    ManualIntakeWorkbench,
    ManualSolveWorkbench,
    SolveContext,
    SolveResult,
    RuntimePreparationError,
    SecureCodexSolveRunner,
    WorkbenchError,
    submission_capability,
)


def _config(tmp_path: Path, *, routing: bool = True) -> AppConfig:
    raw = default_config_mapping("Manual CTF", team_id="team-a", member_name="alice")
    raw["model_routing"]["enabled"] = routing
    raw["model_routing"]["config_path"] = str(
        Path(__file__).parents[1] / "config" / "model-routing.yaml"
    )
    raw["member"]["owned_categories"] = ["pwn", "web"]
    path = tmp_path / "local.team-a.alice.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return AppConfig.from_file(path)


def _manifest(config: AppConfig, entries: str) -> None:
    root = config.incoming_contest_dir()
    root.mkdir(parents=True)
    (root / "contest.md").write_text(
        "# 대회명: Manual CTF\n\n## 문제 목록\n\n" + entries,
        encoding="utf-8",
    )


def _source(config: AppConfig, category: str, name: str, filename: str = "challenge.txt") -> Path:
    root = config.incoming_contest_dir() / category / name
    root.mkdir(parents=True)
    (root / filename).write_text("authorized challenge input\n", encoding="utf-8")
    return root


@dataclass
class RecordingRunner:
    result: SolveResult = SolveResult("COMPLETED", "analysis complete")
    contexts: list[SolveContext] | None = None

    def run(self, context: SolveContext) -> SolveResult:
        if self.contexts is None:
            self.contexts = []
        self.contexts.append(context)
        return self.result


def test_one_bad_zip_does_not_block_sibling_intake_report(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _manifest(config, """### pwn/Broken
- 설명: malformed archive

### web/Healthy
- 설명: plain source
""")
    broken = config.incoming_contest_dir() / "pwn"
    broken.mkdir()
    (broken / "Broken.zip").write_bytes(b"not a zip")
    _source(config, "web", "Healthy")

    reports = ManualIntakeWorkbench(config).run()

    assert {report.challenge.name for report in reports} == {"Broken", "Healthy"}
    by_name = {report.challenge.name: report for report in reports}
    assert by_name["Broken"].status == "blocked"
    assert by_name["Broken"].report_path.is_file()
    assert by_name["Healthy"].status == "ready"
    assert by_name["Healthy"].report_path.is_file()
    assert by_name["Healthy"].workspace.joinpath("challenge.txt").is_file()
    assert "Tactical starting point" in by_name["Healthy"].report_path.read_text(encoding="utf-8")


def test_scoreless_challenge_can_be_intaked_and_started(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _manifest(config, """### pwn/NBB
- 설명: score intentionally omitted
""")
    _source(config, "pwn", "NBB")
    runner = RecordingRunner()

    reports = ManualIntakeWorkbench(config).run()
    result = ManualSolveWorkbench(config, runner=runner).start("NBB", max_subworkers=0)

    assert reports[0].challenge.score is None
    assert reports[0].status == "ready"
    assert result.status == "COMPLETED"
    assert runner.contexts and runner.contexts[0].challenge.name == "NBB"


def test_disabled_model_routing_fails_before_session_creation(tmp_path: Path) -> None:
    config = _config(tmp_path, routing=False)
    _manifest(config, """### pwn/NBB
- 설명: ready
""")
    _source(config, "pwn", "NBB")
    runner = RecordingRunner()

    with pytest.raises(WorkbenchError, match="model routing is disabled"):
        ManualSolveWorkbench(config, runner=runner).start("NBB")

    assert runner.contexts is None
    assert not (config.output_contest_dir() / "pwn-nbb" / "session.json").exists()


def test_solving_one_challenge_never_creates_another_challenge_worker(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _manifest(config, """### pwn/NBB
- 설명: selected

### web/Other
- 설명: must remain idle
""")
    _source(config, "pwn", "NBB")
    _source(config, "web", "Other")
    runner = RecordingRunner()

    ManualSolveWorkbench(config, runner=runner).start("NBB", max_subworkers=3)

    assert runner.contexts and [item.challenge.name for item in runner.contexts] == ["NBB"]
    assert (config.output_contest_dir() / "pwn-nbb" / "session.json").is_file()
    assert not (config.output_contest_dir() / "web-other" / "session.json").exists()


def test_runner_cannot_exceed_human_subworker_ceiling(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _manifest(config, """### pwn/NBB
- 설명: selected
""")
    _source(config, "pwn", "NBB")
    root = config.output_contest_dir() / "pwn-nbb" / "workers"
    runner = RecordingRunner(SolveResult(
        "COMPLETED", subworkers=tuple(
            {"worker_id": str(index), "artifact_path": str(root / str(index))}
            for index in range(3)
        ),
    ))

    with pytest.raises(WorkbenchError, match="subworker ceiling"):
        ManualSolveWorkbench(config, runner=runner).start("NBB", max_subworkers=2)

    session = json.loads((config.output_contest_dir() / "pwn-nbb" / "session.json").read_text())
    assert session["status"] == "FAILED"


def test_subworker_artifact_path_cannot_escape_selected_challenge(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _manifest(config, """### pwn/NBB
- 설명: selected
""")
    _source(config, "pwn", "NBB")
    runner = RecordingRunner(SolveResult(
        "COMPLETED",
        subworkers=({"worker_id": "terra-01", "artifact_path": str(tmp_path / "escape")},),
    ))

    with pytest.raises(WorkbenchError, match="artifact path escaped"):
        ManualSolveWorkbench(config, runner=runner).start("NBB", max_subworkers=1)


def test_no_flag_submission_command_or_capability_exists() -> None:
    parser = _build_parser()
    subcommands = parser._subparsers._group_actions[0].choices

    assert "submit" not in subcommands
    assert "tui" not in subcommands
    assert "parse" not in subcommands
    assert submission_capability() is False


def test_completed_session_is_not_left_running_and_no_tui_is_required(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _manifest(config, """### pwn/NBB
- 설명: selected
""")
    _source(config, "pwn", "NBB")

    ManualSolveWorkbench(config, runner=RecordingRunner()).start("NBB", priority="high")

    session = json.loads((config.output_contest_dir() / "pwn-nbb" / "session.json").read_text())
    assert session["status"] == "COMPLETED"
    assert session["priority"] == "high"
    assert session["automatic_submission"] is False


def test_runtime_preparation_failure_blocks_only_selected_session(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _manifest(config, """### pwn/NBB
- 설명: selected

### web/Other
- 설명: sibling
""")
    _source(config, "pwn", "NBB")
    _source(config, "web", "Other")

    class BrokenRuntime:
        def run(self, context: SolveContext) -> SolveResult:
            raise RuntimePreparationError("reviewed runtime image is unavailable")

    with pytest.raises(RuntimePreparationError, match="runtime image"):
        ManualSolveWorkbench(config, runner=BrokenRuntime()).start("NBB")

    selected = json.loads((config.output_contest_dir() / "pwn-nbb" / "session.json").read_text())
    assert selected["status"] == "BLOCKED"
    assert not (config.output_contest_dir() / "web-other" / "session.json").exists()


def test_operator_pause_is_observed_by_active_secure_session(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _manifest(config, """### pwn/NBB
- 설명: selected
""")
    _source(config, "pwn", "NBB")
    runner = RecordingRunner()
    workbench = ManualSolveWorkbench(config, runner=runner)
    workbench.start("NBB", max_subworkers=0)
    assert runner.contexts
    context = runner.contexts[0]
    session_path = context.artifact_root / "session.json"
    payload = json.loads(session_path.read_text(encoding="utf-8"))
    payload["status"] = "RUNNING"
    session_path.write_text(json.dumps(payload), encoding="utf-8")
    cancellation, stop = ThreadEvent(), ThreadEvent()
    watcher = Thread(
        target=SecureCodexSolveRunner._watch_operator_state,
        args=(context, cancellation, stop), daemon=True,
    )
    watcher.start()

    workbench.set_state("NBB", "PAUSED")

    assert cancellation.wait(2)
    assert SecureCodexSolveRunner._requested_terminal_state(context, cancellation) == "PAUSED"
    stop.set()
    watcher.join(timeout=1)


def test_lead_protocol_accepts_only_bounded_structured_worker_and_state_lines() -> None:
    output = """CTF_OS_SUBWORKER_REQUEST: {"role":"terra","scope":"exploit implementation","task":"build replay"}
CTF_OS_SUBWORKER_REQUEST: {"role":"unknown","scope":"bad","task":"bad"}
CTF_OS_SESSION_STATE: {"status":"continue","reason":"need implementation result"}
"""

    requests = SecureCodexSolveRunner._parse_requests(output)
    state = SecureCodexSolveRunner._parse_lead_state(output)

    assert [(item.role, item.scope) for item in requests] == [("terra", "exploit implementation")]
    assert state == ("continue", "need implementation result")
