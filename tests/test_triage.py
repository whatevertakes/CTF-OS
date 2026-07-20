from pathlib import Path
import json
import subprocess

import pytest

from ctf_os.challenge import resolve_selector
from ctf_os.contest import discover_contests
from ctf_os.intake import run_intake
from ctf_os.triage import (
    TriageError, finalize_triage, load_optional_final_triage, prepare_triage,
    require_final_triage,
)
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
    with pytest.raises(TriageError, match="No current finalized"):
        require_final_triage(repo, manifest, resolve_selector(manifest.challenges, "1"))


def test_missing_triage_is_optional_and_current_triage_is_included(repo: Path) -> None:
    write_contest(repo, """# Demo Triage
### misc/one
- Description: warmup encoding
""", "Demo Triage")
    source = repo / "incoming" / "Demo Triage" / "misc" / "one"
    source.mkdir(parents=True)
    (source / "message.txt").write_text("hello")
    run_intake(repo, "Demo Triage")

    without_triage = subprocess.run(
        ["python", "-m", "ctf_os.agent_tools", "--repo", str(repo), "prepare-challenge", "1", "--contest", "Demo Triage"],
        capture_output=True, text=True, check=True,
    )
    prepared_without_triage = json.loads(without_triage.stdout)["result"]
    assert prepared_without_triage["triage_available"] is False
    assert prepared_without_triage["triage_recommendation"] == {}
    assert prepared_without_triage["contest_triage"] is None
    launch_without_triage = prepared_without_triage["solve_launch_context"]["contest_triage"]
    assert launch_without_triage == {
        "available": False,
        "recommendation": {},
        "reasons": [],
        "baseline": {},
        "setup": {},
        "attack_surface_clarity": None,
        "recommended_tools": [],
        "recommended_playbook": {},
    }

    strict_runtime = subprocess.run(
        ["python", "-m", "ctf_os.agent_tools", "--repo", str(repo), "resource-history", "1", "--contest", "Demo Triage"],
        capture_output=True, text=True,
    )
    assert strict_runtime.returncode == 0

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
    prepared_with_triage = json.loads(ready.stdout)["result"]
    assert prepared_with_triage["triage_available"] is True
    assert prepared_with_triage["triage_recommendation"]["label"] == "Priority #1"
    assert prepared_with_triage["contest_triage"]["recommendation"]["rank"] == 1
    launch_triage = prepared_with_triage["solve_launch_context"]["contest_triage"]
    assert launch_triage["available"] is True
    assert launch_triage["recommendation"]["label"] == "Priority #1"
    assert launch_triage["baseline"]["difficulty"] == "easy"
    assert launch_triage["setup"]["cost"] in {"low", "medium", "high"}
    assert launch_triage["attack_surface_clarity"] in {"clear", "partial", "limited"}
    assert launch_triage["reasons"]
    assert launch_triage["recommended_tools"]
    assert launch_triage["recommended_playbook"]["path"].endswith("misc.md")


def test_stale_final_triage_is_ignored_without_rewriting_it(repo: Path) -> None:
    write_contest(repo, """# Demo Triage
### misc/one
- Description: warmup encoding
""", "Demo Triage")
    source = repo / "incoming" / "Demo Triage" / "misc" / "one"
    source.mkdir(parents=True)
    (source / "message.txt").write_text("hello")
    run_intake(repo, "Demo Triage")
    prepared_result = prepare_triage(repo, "Demo Triage")
    prepared = json.loads(Path(prepared_result["input_path"]).read_text())
    result = finalize_triage(repo, "Demo Triage", {
        "assessments": [_assessment(prepared, 1, "priority", 1)],
    })
    triage_path = Path(result["index_path"])
    triage = json.loads(triage_path.read_text())
    triage["source"]["intake_sha256"] = "0" * 64
    triage_path.write_text(json.dumps(triage, sort_keys=True))
    stale_bytes = triage_path.read_bytes()

    command = subprocess.run(
        ["python", "-m", "ctf_os.agent_tools", "--repo", str(repo), "prepare-challenge", "1", "--contest", "Demo Triage"],
        capture_output=True, text=True, check=True,
    )
    payload = json.loads(command.stdout)["result"]

    assert payload["triage_available"] is False
    assert payload["triage_recommendation"] == {}
    assert payload["contest_triage"] is None
    assert payload["solve_launch_context"]["contest_triage"]["available"] is False
    assert payload["solve_launch_context"]["contest_triage"]["recommendation"] == {}
    assert triage_path.read_bytes() == stale_bytes

    manifest = discover_contests(repo / "incoming")[0]
    challenge = resolve_selector(manifest.challenges, "1")
    assert load_optional_final_triage(repo, manifest, challenge) is None


def test_malformed_current_triage_is_rejected(repo: Path) -> None:
    write_contest(repo, """# Demo Triage
### misc/one
- Description: warmup encoding
""", "Demo Triage")
    source = repo / "incoming" / "Demo Triage" / "misc" / "one"
    source.mkdir(parents=True)
    (source / "message.txt").write_text("hello")
    intake = run_intake(repo, "Demo Triage")
    triage_path = repo / "output" / intake["contest"]["slug"] / "triage.json"
    triage_path.write_text("{not-json")

    command = subprocess.run(
        ["python", "-m", "ctf_os.agent_tools", "--repo", str(repo), "prepare-challenge", "1", "--contest", "Demo Triage"],
        capture_output=True, text=True,
    )

    assert command.returncode == 2
    assert "Challenge Triage index is unreadable" in json.loads(command.stdout)["error"]
