from pathlib import Path
import subprocess

from ctf_os.challenge import resolve_selector
from ctf_os.contest import discover_contests
from ctf_os.flags import verify_and_record
from ctf_os.intake import run_intake
from conftest import write_contest


def test_offline_intake_to_solver_verification_smoke(repo: Path) -> None:
    write_contest(repo, "# Smoke CTF\n- Flag Format: SMOKE{...}\n### crypto/Toy\n- Description: output the constant\n", "Smoke CTF")
    source = repo / "incoming" / "Smoke CTF" / "crypto" / "Toy"
    source.mkdir(parents=True)
    (source / "challenge.py").write_text("print('SMOKE{offline-proof}')\n")
    intake = run_intake(repo, "Smoke CTF")
    manifest = discover_contests(repo / "incoming")[0]
    challenge = resolve_selector(manifest.challenges, "1번")
    record = intake["challenges"][0]
    solve_root = Path(record["workspace_path"])
    exploit = solve_root / "exploit"
    exploit.mkdir()
    (exploit / "solve.py").write_text("print('SMOKE{offline-proof}')\n")
    verified = verify_and_record(
        solve_root, flag="SMOKE{offline-proof}", pattern=challenge.flag_pattern,
        has_remote=False, local_reproduced=True, remote_reproduced=False,
        independent_rerun=True, reproduce_command="python exploit/solve.py",
    )
    assert verified["status"] == "READY_FOR_HUMAN_SUBMISSION"
    assert (solve_root / "evidence.log").is_file()
    rerun = subprocess.run(["bash", str(solve_root / "reproduce.sh")], cwd=repo, capture_output=True, text=True, check=True)
    assert rerun.stdout.strip() == "SMOKE{offline-proof}"
