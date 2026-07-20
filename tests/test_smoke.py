from pathlib import Path
import json
import subprocess

from ctf_os.challenge import resolve_selector
from ctf_os.contest import discover_contests
from ctf_os.flags import verify_and_record
from ctf_os.preflight import prepare_selected_challenge
from conftest import write_contest


def test_offline_preflight_to_solver_verification_smoke(repo: Path) -> None:
    write_contest(repo, "# Smoke CTF\n- Flag Format: SMOKE{...}\n### crypto/Toy\n- Description: output the constant\n", "Smoke CTF")
    source = repo / "incoming" / "Smoke CTF" / "crypto" / "Toy"
    source.mkdir(parents=True)
    (source / "challenge.py").write_text("print('SMOKE{offline-proof}')\n")
    manifest = discover_contests(repo / "incoming")[0]
    challenge = resolve_selector(manifest.challenges, "1번")
    record = prepare_selected_challenge(repo, manifest, challenge)
    solve_root = Path(record["workspace_path"])
    exploit = solve_root / "exploit"
    exploit.mkdir()
    (exploit / "solve.py").write_text("print('SMOKE{offline-proof}')\n")
    fingerprint = record["source_fingerprint"]
    receipts = [
        {"event": "replay_exec", "receipt_id": "local-one", "exit_code": 0, "stdout": "SMOKE{offline-proof}", "input_fingerprint": fingerprint},
        {"event": "replay_exec", "receipt_id": "local-two", "exit_code": 0, "stdout": "SMOKE{offline-proof}", "input_fingerprint": fingerprint},
    ]
    (solve_root / "evidence.log").write_text("\n".join(json.dumps(item) for item in receipts) + "\n")
    verified = verify_and_record(
        solve_root, flag="SMOKE{offline-proof}", pattern=challenge.flag_pattern,
        has_remote=False, local_reproduced=True, remote_reproduced=False,
        independent_rerun=True, reproduce_argv=["python3", "/artifacts/exploit/solve.py"],
        evidence_refs={"local": "local-one", "independent": "local-two"},
        input_fingerprint=fingerprint,
    )
    assert verified["status"] == "READY_FOR_HUMAN_SUBMISSION"
    assert (solve_root / "evidence.log").is_file()
    wrapper = (solve_root / "reproduce.sh").read_text()
    assert "ctf_os.agent_tools" in wrapper and "replay" in wrapper
    assert "solve.py" not in wrapper
