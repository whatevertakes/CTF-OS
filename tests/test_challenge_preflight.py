from __future__ import annotations

import json
from pathlib import Path
import subprocess
import zipfile

from ctf_os.contest import discover_contests
from ctf_os.preflight import _legacy_source_fingerprint
from ctf_os.workspace import challenge_root
from conftest import write_contest


def _write_two_challenges(repo: Path, *, broken_b: bool = False) -> None:
    write_contest(
        repo,
        """# Isolation CTF
- Flag format: ISO{...}
### misc/A
- Description: selected A
### misc/B
- Description: sibling B
""",
        "Isolation CTF",
    )
    root = repo / "incoming" / "Isolation CTF" / "misc"
    (root / "A").mkdir(parents=True)
    (root / "A" / "a.txt").write_text("alpha", encoding="utf-8")
    if broken_b:
        (root / "B.zip").write_bytes(b"damaged zip")
    else:
        (root / "B").mkdir()
        (root / "B" / "b.txt").write_text("bravo", encoding="utf-8")


def _prepare(repo: Path, selector: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "python", "-m", "ctf_os.agent_tools", "--repo", str(repo),
            "prepare-challenge", selector, "--contest", "Isolation CTF",
        ],
        capture_output=True,
        text=True,
    )


def _result(completed: subprocess.CompletedProcess[str]) -> dict[str, object]:
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout)["result"]


def test_prepare_materializes_only_selected_challenge_and_preserves_admin_files(repo: Path) -> None:
    _write_two_challenges(repo)
    manifest = discover_contests(repo / "incoming")[0]
    contest_output = repo / "output" / manifest.slug
    contest_output.mkdir(parents=True)
    triage = contest_output / "triage.json"
    board = contest_output / "TRIAGE.md"
    triage.write_bytes(b'{"legacy":true}\n')
    board.write_bytes(b"legacy board\n")
    before = (triage.read_bytes(), board.read_bytes())

    payload = _result(_prepare(repo, "misc/A"))

    a_root = Path(payload["solve_root"])
    b_root = challenge_root(repo, manifest, manifest.challenges[1])
    record = json.loads((a_root / "CHALLENGE-PREFLIGHT.json").read_text())
    rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    assert (a_root / "input" / "a.txt").read_text() == "alpha"
    assert not b_root.exists()
    assert not list(contest_output.glob("intake.json"))
    assert (triage.read_bytes(), board.read_bytes()) == before
    assert record["challenge"]["key"] == "misc/A"
    assert not any(key in record for key in ("contest", "challenges", "summary"))
    assert "sibling B" not in rendered and "b.txt" not in rendered


def test_corrupt_sibling_blocks_only_when_it_is_selected(repo: Path) -> None:
    _write_two_challenges(repo, broken_b=True)

    a = _result(_prepare(repo, "misc/A"))
    a_root = Path(a["solve_root"])
    a_run = Path(a["run_root"])
    a_before = (a_root / "CHALLENGE-PREFLIGHT.json").read_bytes()
    b = _prepare(repo, "misc/B")

    assert b.returncode == 2
    assert "damaged ZIP" in json.loads(b.stdout)["error"]
    manifest = discover_contests(repo / "incoming")[0]
    b_root = challenge_root(repo, manifest, manifest.challenges[1])
    b_record = json.loads((b_root / "CHALLENGE-PREFLIGHT.json").read_text())
    assert b_record["status"] == "BLOCKED"
    assert "damaged ZIP" in b_record["blockers"][0]
    assert (a_root / "CHALLENGE-PREFLIGHT.json").read_bytes() == a_before
    assert json.loads((a_run / "STATE.json").read_text())["status"] == "SWARM_READY"


def test_parallel_prepare_uses_independent_challenge_locks_and_records(repo: Path) -> None:
    _write_two_challenges(repo)
    commands = []
    for selector in ("misc/A", "misc/B"):
        commands.append(subprocess.Popen(
            [
                "python", "-m", "ctf_os.agent_tools", "--repo", str(repo),
                "prepare-challenge", selector, "--contest", "Isolation CTF",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ))
    completed = [process.communicate(timeout=30) + (process.returncode,) for process in commands]
    assert all(code == 0 for _stdout, _stderr, code in completed), completed
    payloads = [json.loads(stdout)["result"] for stdout, _stderr, _code in completed]
    roots = [Path(payload["solve_root"]) for payload in payloads]
    assert roots[0] != roots[1]
    assert all((root / "CHALLENGE-PREFLIGHT.json").is_file() for root in roots)
    assert all((root / "SOLVE-LAUNCH.json").is_file() for root in roots)
    assert (roots[0] / "input" / "a.txt").is_file()
    assert (roots[1] / "input" / "b.txt").is_file()
    assert not list((repo / "output").glob("*/intake.json"))


def test_sibling_metadata_remote_and_source_changes_do_not_stale_selected_runtime(repo: Path) -> None:
    _write_two_challenges(repo)
    a = _result(_prepare(repo, "misc/A"))
    b = _result(_prepare(repo, "misc/B"))
    a_root = Path(a["solve_root"])
    b_root = Path(b["solve_root"])
    a_run = Path(a["run_root"])
    b_run = Path(b["run_root"])
    a_preflight = (a_root / "CHALLENGE-PREFLIGHT.json").read_bytes()
    a_state = (a_run / "STATE.json").read_bytes()
    receipt = a_run / "flag-receipts" / "remote-a.json"
    receipt.parent.mkdir(exist_ok=True)
    receipt.write_bytes(b'{"flag":"ISO{a}"}\n')
    b_before = json.loads((b_root / "CHALLENGE-PREFLIGHT.json").read_text())
    manifest_path = repo / "incoming" / "Isolation CTF" / "contest.md"
    manifest_path.write_text(
        """# Isolation CTF
- Flag format: ISO{...}
### misc/A
- Description: selected A
### misc/B
- Description: changed sibling B
- Remote: https://example.com/b
""",
        encoding="utf-8",
    )
    (repo / "incoming" / "Isolation CTF" / "misc" / "B" / "b.txt").write_text(
        "changed bravo", encoding="utf-8",
    )

    strict = subprocess.run(
        [
            "python", "-m", "ctf_os.agent_tools", "--repo", str(repo),
            "resource-history", "misc/A", "--contest", "Isolation CTF",
        ],
        capture_output=True,
        text=True,
    )
    assert strict.returncode == 0, strict.stdout
    _result(_prepare(repo, "misc/A"))
    b_after_payload = _result(_prepare(repo, "misc/B"))
    b_after = json.loads(Path(b_after_payload["preflight_record_path"]).read_text())

    assert (a_root / "CHALLENGE-PREFLIGHT.json").read_bytes() == a_preflight
    assert (a_run / "STATE.json").read_bytes() == a_state
    assert receipt.read_bytes() == b'{"flag":"ISO{a}"}\n'
    assert b_after["source_fingerprint"] != b_before["source_fingerprint"]
    assert b_after["challenge"]["description"] == "changed sibling B"


def test_selected_source_change_invalidates_only_selected_workspace(repo: Path) -> None:
    _write_two_challenges(repo)
    a = _result(_prepare(repo, "misc/A"))
    b = _result(_prepare(repo, "misc/B"))
    a_root = Path(a["solve_root"])
    b_root = Path(b["solve_root"])
    a_run = Path(a["run_root"])
    b_run = Path(b["run_root"])
    a_before = json.loads((a_root / "CHALLENGE-PREFLIGHT.json").read_text())
    a_state_path = a_run / "STATE.json"
    a_state = json.loads(a_state_path.read_text())
    a_state.update({"status": "SUBMISSION_RECOMMENDED", "flag_candidate": "ISO{old}"})
    a_state_path.write_text(json.dumps(a_state, sort_keys=True))
    (a_run / "RESULT.md").write_text("old result", encoding="utf-8")
    protected = {}
    for relative, content in {
        "ATTACK_EVENTS.jsonl": '{"type":"COMMAND_EXECUTED"}\n',
        "flag-receipts/remote-b.json": '{"flag":"ISO{b}"}\n',
        "workers/tool-driven/artifacts/probe.txt": "preserve\n",
    }.items():
        path = b_run / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        protected[relative] = path.read_bytes()
    protected["CHALLENGE-PREFLIGHT.json"] = (b_root / "CHALLENGE-PREFLIGHT.json").read_bytes()
    protected["SOLVE-LAUNCH.json"] = (b_root / "SOLVE-LAUNCH.json").read_bytes()
    protected["STATE.json"] = (b_run / "STATE.json").read_bytes()
    protected["evidence.log"] = (b_run / "evidence.log").read_bytes()
    (repo / "incoming" / "Isolation CTF" / "misc" / "A" / "a.txt").write_text(
        "changed alpha", encoding="utf-8",
    )

    refreshed = _result(_prepare(repo, "misc/A"))
    a_after = json.loads(Path(refreshed["preflight_record_path"]).read_text())
    new_run = Path(refreshed["run_root"])
    state_after = json.loads((new_run / "STATE.json").read_text())

    assert a_after["source_fingerprint"] != a_before["source_fingerprint"]
    assert (a_root / "input" / "a.txt").read_text() == "changed alpha"
    assert state_after["status"] == "SWARM_READY" and state_after["flag_candidate"] is None
    assert a_state_path.exists()
    assert json.loads(a_state_path.read_text())["flag_candidate"] == "ISO{old}"
    assert (a_run / "RESULT.md").read_text() == "old result"
    assert new_run != a_run
    for relative, before in protected.items():
        base = b_root if relative in {"CHALLENGE-PREFLIGHT.json", "SOLVE-LAUNCH.json"} else b_run
        assert (base / relative).read_bytes() == before


def test_prepare_and_launch_schema_have_no_contest_triage_fields(repo: Path) -> None:
    _write_two_challenges(repo)
    payload = _result(_prepare(repo, "misc/A"))
    rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True).casefold()
    for forbidden in (
        "contest_triage", "triage_available", "triage_recommendation", "difficulty",
        "estimated_solve_time", "success_probability", "recommendation rank",
        "recommendation bucket",
    ):
        assert forbidden not in rendered


def test_legacy_fingerprint_migrates_terminal_run_without_losing_receipt(repo: Path) -> None:
    _write_two_challenges(repo)
    manifest = discover_contests(repo / "incoming")[0]
    challenge = manifest.challenges[0]
    source = repo / "incoming" / "Isolation CTF" / "misc" / "A"
    workspace = challenge_root(repo, manifest, challenge)
    workspace.mkdir(parents=True)
    legacy_fingerprint = _legacy_source_fingerprint(challenge, [source])
    (workspace / "STATE.json").write_text(json.dumps({
        "challenge_id": challenge.id, "input_fingerprint": legacy_fingerprint,
        "status": "SUBMISSION_RECOMMENDED", "flag_candidate": "ISO{legacy}",
        "remote_flag_receipt": "flag-receipts/legacy.json",
        "submission_recommended": True, "flag_history": [{"candidate": "ISO{legacy}"}],
    }), encoding="utf-8")
    receipts = workspace / "flag-receipts"
    receipts.mkdir()
    (receipts / "legacy.json").write_text('{"candidate":"ISO{legacy}"}\n', encoding="utf-8")

    payload = _result(_prepare(repo, "misc/A"))
    state = json.loads((Path(payload["run_root"]) / "STATE.json").read_text())
    preflight = json.loads(Path(payload["preflight_record_path"]).read_text())

    assert state["status"] == "SUBMISSION_RECOMMENDED"
    assert state["flag_candidate"] == "ISO{legacy}"
    assert state["input_fingerprint"] == preflight["source_fingerprint"]
    assert state["fingerprint_scheme"] == preflight["fingerprint_scheme"] == "challenge-local-v2"
    assert (Path(payload["run_root"]) / "flag-receipts" / "legacy.json").is_file()


def test_prepare_recovers_missing_run_state_with_bound_fingerprint(repo: Path) -> None:
    _write_two_challenges(repo)
    first = _result(_prepare(repo, "misc/A"))
    Path(first["run_root"]).joinpath("STATE.json").unlink()

    repaired = _result(_prepare(repo, "misc/A"))
    state = json.loads((Path(repaired["run_root"]) / "STATE.json").read_text())
    record = json.loads(Path(repaired["preflight_record_path"]).read_text())
    runtime = subprocess.run([
        "python", "-m", "ctf_os.agent_tools", "--repo", str(repo),
        "resource-history", "misc/A", "--contest", "Isolation CTF",
    ], capture_output=True, text=True)

    assert state["input_fingerprint"] == record["source_fingerprint"]
    assert state["fingerprint_scheme"] == "challenge-local-v2"
    assert runtime.returncode == 0, runtime.stdout + runtime.stderr


def test_prepare_repairs_missing_or_tampered_preflight_companions(repo: Path) -> None:
    _write_two_challenges(repo)
    first = _result(_prepare(repo, "misc/A"))
    workspace = Path(first["solve_root"])
    (workspace / "inventory.json").unlink()
    (workspace / "CONTEXT.md").write_text("tampered", encoding="utf-8")

    _result(_prepare(repo, "misc/A"))
    record = json.loads((workspace / "CHALLENGE-PREFLIGHT.json").read_text())
    inventory = json.loads((workspace / "inventory.json").read_text())

    assert inventory == {"schema_version": 1, "files": record["files"]}
    assert (workspace / "CONTEXT.md").read_text() != "tampered"


def test_session_input_prepares_unlisted_challenge_without_rewriting_manifest(repo: Path) -> None:
    manifest_path = write_contest(repo, "# Session CTF\n", "Session CTF")
    problems = manifest_path.with_name("problems.txt")
    problems.write_text(
        "대회명: Session CTF\n\nmisc/Sibling\n설명: unrelated sibling\n",
        encoding="utf-8",
    )
    upload = manifest_path.parent / "uploads" / "prompt.bin"
    upload.parent.mkdir()
    upload.write_bytes(b"prompt supplied challenge")
    before = manifest_path.read_bytes()
    packet = json.dumps({
        "category": "misc", "name": "PromptOnly", "description": "from current Sol session",
        "flag_format": "SESS{...}", "remotes": ["nc 8.8.8.8 31337"],
        "source_paths": ["uploads/prompt.bin"],
    })
    prepared = subprocess.run([
        "python", "-m", "ctf_os.agent_tools", "--repo", str(repo),
        "prepare-challenge", "misc/PromptOnly", "--contest", "Session CTF",
        "--session-input-json", packet,
    ], capture_output=True, text=True)
    payload = _result(prepared)
    workspace = Path(payload["solve_root"])
    record = json.loads((workspace / "CHALLENGE-PREFLIGHT.json").read_text())
    problems.write_text(
        "대회명: Session CTF\n\nmisc/Sibling\n설명: changed sibling\n",
        encoding="utf-8",
    )
    runtime = subprocess.run([
        "python", "-m", "ctf_os.agent_tools", "--repo", str(repo),
        "resource-history", "misc/PromptOnly", "--contest", "Session CTF",
    ], capture_output=True, text=True)

    assert manifest_path.read_bytes() == before
    assert (workspace / "SESSION-INPUT.json").is_file()
    assert (workspace / "input" / "prompt.bin").read_bytes() == b"prompt supplied challenge"
    assert record["authorized_targets"][0]["host"] == "8.8.8.8"
    assert runtime.returncode == 0, runtime.stdout + runtime.stderr
    contest_output = workspace.parents[1]
    for artifact in ("intake.json", "triage.json", "INTAKE.md", "TRIAGE.md"):
        assert not (contest_output / artifact).exists()
