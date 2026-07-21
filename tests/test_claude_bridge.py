from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess

from ctf_os.claude_bridge import dispatch_claude_rescue


def test_prepare_bridge_targets_separate_runtime(
    tmp_path: Path, monkeypatch,
) -> None:
    runtime = tmp_path / "CTF-OS-claude"
    (runtime / "ctf_os").mkdir(parents=True)
    (runtime / "ctf_os" / "rescue.py").write_text("# runtime marker\n")
    (runtime / "pyproject.toml").write_text("[project]\nname='runtime-marker'\nversion='0'\n")
    source = tmp_path / "CTF-OS-main"
    source.mkdir()
    monkeypatch.setenv("CTF_OS_CLAUDE_HOME", str(runtime))
    observed: dict[str, object] = {}

    def fake_run(argv, **kwargs):
        observed["argv"] = argv
        observed["cwd"] = kwargs["cwd"]
        return subprocess.CompletedProcess(
            argv, 0, json.dumps({"ok": True, "result": {"path": str(runtime / "runs" / "x")}}), "",
        )

    monkeypatch.setattr("ctf_os.claude_bridge.subprocess.run", fake_run)
    args = argparse.Namespace(
        command="rescue-prepare", selector="1", contest="demo",
        run_id="run-1", mode="BLOCKER_BREAK", profile="standard",
        objective="build poc", current_blocker="unknown byte",
        leading_exploit_path="controlled write", path_not_to_repeat=[],
        operation_id="op-1", lead_model=None, research_policy="offline",
        session_id="sol-main", session_role="sol", parent_session_id="sol-main",
        recover_stale=False,
    )

    result = dispatch_claude_rescue(source, args)

    argv = observed["argv"]
    assert isinstance(argv, list)
    assert argv[:4] == ["uv", "run", "--project", str(runtime)]
    assert argv[argv.index("--repo") + 1] == str(source)
    assert result["path"].startswith(str(runtime / "runs"))
    assert observed["cwd"] == runtime
