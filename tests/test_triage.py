from pathlib import Path
import json
import subprocess

import pytest

from ctf_os.challenge import resolve_selector
from ctf_os.contest import discover_contests
from ctf_os.intake import run_intake
from ctf_os.triage import TriageError, finalize_triage, prepare_triage, require_final_triage
from conftest import write_contest


def _assessment(prepared: dict[str, object], number: int, recommendation: str, rank: int | None = None) -> dict[str, object]:
    record = next(item for item in prepared["challenges"] if item["number"] == number)
    facts = [item["id"] for item in record["evidence_facts"]]
    result: dict[str, object] = {
        "number": number,
        "recommendation": recommendation,
        "reason_fact_ids": facts[:2],
    }
    if rank is not None:
        result["rank"] = rank
    return result


def test_triage_builds_static_context_and_evidence_backed_board(repo: Path) -> None:
    write_contest(repo, """# Demo Triage
### pwn/baby-bof
- Score: 100
- Description: warmup buffer overflow
### web/memo
- Score: 200
- Description: Flask upload service
### forensic/missing
- Description: no downloadable input yet
""", "Demo Triage")
    pwn = repo / "incoming" / "Demo Triage" / "pwn" / "baby-bof"
    pwn.mkdir(parents=True)
    (pwn / "chall.c").write_text("int main(void) { return 0; }\n")
    web = repo / "incoming" / "Demo Triage" / "web" / "memo"
    web.mkdir(parents=True)
    (web / "requirements.txt").write_text("Flask\n")
    (web / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n")

    run_intake(repo, "Demo Triage")
    prepared_result = prepare_triage(repo, "Demo Triage")
    prepared = json.loads(Path(prepared_result["input_path"]).read_text())
    baby = prepared["challenges"][0]

    assert prepared["summary"] == {"total": 3, "ready": 2, "blocked": 1}
    assert "files" not in baby and "source_paths" not in baby
    assert baby["baseline"] == {
        "difficulty": "easy", "estimated_solve_time": "10~20m", "success_probability": "high",
    }
    assert "stack overflow" in baby["initial_attack_surface"]
    assert "Priority score is internal" in Path(prepared_result["context_path"]).read_text()

    result = finalize_triage(repo, "Demo Triage", {
        "assessments": [
            _assessment(prepared, 1, "priority", 1),
            _assessment(prepared, 2, "priority", 2),
        ],
    })
    board = Path(result["board_path"]).read_text()
    index = json.loads(Path(result["index_path"]).read_text())

    assert "**READY** 2 / 3" in board and "**BLOCKED** 1" in board
    assert "### 01 pwn/baby-bof" in board and "⭐⭐⭐⭐⭐" in board and "Priority #1" in board
    assert "Initial attack surface: stack overflow" in board
    assert "priority_score" not in board
    assert isinstance(index["challenges"][0]["priority_score"], int)
    assert len(index["challenges"][0]["reasons"]) == 2

    manifest = discover_contests(repo / "incoming")[0]
    assert require_final_triage(repo, manifest, resolve_selector(manifest.challenges, "1"))["recommendation"]["rank"] == 1

    run_intake(repo, "Demo Triage")
    assert not Path(result["index_path"]).exists()
    with pytest.raises(TriageError, match="not found"):
        require_final_triage(repo, manifest, resolve_selector(manifest.challenges, "1"))


def test_triage_cli_finalization_and_solve_gate(repo: Path) -> None:
    write_contest(repo, """# Demo Triage
### misc/one
- Description: warmup encoding
""", "Demo Triage")
    source = repo / "incoming" / "Demo Triage" / "misc" / "one"
    source.mkdir(parents=True)
    (source / "message.txt").write_text("hello")
    run_intake(repo, "Demo Triage")

    blocked = subprocess.run(
        ["python", "-m", "ctf_os.agent_tools", "--repo", str(repo), "prepare-challenge", "1", "--contest", "Demo Triage"],
        capture_output=True, text=True,
    )
    assert blocked.returncode == 2
    assert "Challenge Triage board not found" in json.loads(blocked.stdout)["error"]

    prepared_command = subprocess.run(
        ["python", "-m", "ctf_os.agent_tools", "--repo", str(repo), "triage-prepare", "--contest", "Demo Triage"],
        capture_output=True, text=True, check=True,
    )
    prepared_path = json.loads(prepared_command.stdout)["result"]["input_path"]
    prepared = json.loads(Path(prepared_path).read_text())
    payload = {"assessments": [_assessment(prepared, 1, "priority", 1)]}
    finalized = subprocess.run(
        ["python", "-m", "ctf_os.agent_tools", "--repo", str(repo), "triage-finalize", "--contest", "Demo Triage", "--assessments-json", json.dumps(payload)],
        capture_output=True, text=True, check=True,
    )
    assert json.loads(finalized.stdout)["result"]["summary"]["priority"] == 1

    ready = subprocess.run(
        ["python", "-m", "ctf_os.agent_tools", "--repo", str(repo), "prepare-challenge", "1", "--contest", "Demo Triage"],
        capture_output=True, text=True, check=True,
    )
    assert json.loads(ready.stdout)["result"]["triage_recommendation"]["label"] == "Priority #1"
