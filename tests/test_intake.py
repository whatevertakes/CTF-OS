from pathlib import Path
import json
import subprocess
import zipfile

from ctf_os.intake import run_intake
from conftest import write_contest


def _manifest() -> str:
    return """# 대회명: Demo CTF
- 플래그 형식: DEMO{...}
### pwn/Good
- 설명: binary
### rev/Broken
- 설명: bad archive
### web/RemoteOnly
- 설명: service
- 원격: https://example.com/path
"""


def test_intake_isolates_corrupt_zip_and_writes_deep_context(repo: Path) -> None:
    write_contest(repo, _manifest())
    pwn = repo / "incoming" / "Demo CTF" / "pwn"
    pwn.mkdir()
    with zipfile.ZipFile(pwn / "Good.zip", "w") as archive:
        archive.writestr("solve.py", "print('hello')\n")
    rev = repo / "incoming" / "Demo CTF" / "rev"
    rev.mkdir()
    (rev / "Broken.zip").write_bytes(b"not a zip")
    result = run_intake(repo)
    records = result["challenges"]
    assert [record["status"] for record in records] == ["READY", "BLOCKED", "READY"]
    assert "damaged ZIP" in records[1]["blockers"][0]
    good = records[0]
    assert good["files"][0]["sha256"]
    assert good["files"][0]["mime"]
    assert good["archives"][0]["members"] == ["solve.py"]
    output = repo / "output" / result["contest"]["slug"]
    assert (output / "intake.json").is_file()
    assert "[01] READY" in (output / "INTAKE.md").read_text()
    assert Path(good["context_path"]).is_file()


def test_reintake_detects_changes_and_preserves_solve_results(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### misc/X\n- 설명: x\n")
    source = repo / "incoming" / "Demo CTF" / "misc" / "X"
    source.mkdir(parents=True)
    (source / "value.txt").write_text("one")
    first = run_intake(repo)["challenges"][0]
    challenge_root = Path(first["workspace_path"])
    (challenge_root / "RESULT.md").write_text("keep me")
    (source / "value.txt").write_text("two")
    second = run_intake(repo)["challenges"][0]
    assert first["source_fingerprint"] != second["source_fingerprint"]
    assert "invalidated" in (challenge_root / "RESULT.md").read_text()
    assert any(path.read_text() == "keep me" for path in challenge_root.glob("RESULT.stale-*.md"))
    state = __import__("json").loads((challenge_root / "STATE.json").read_text())
    assert state["status"] == "PREPARED" and state["flag_candidate"] is None
    assert (challenge_root / "input" / "value.txt").read_text() == "two"
    assert oct((challenge_root / "input" / "value.txt").stat().st_mode & 0o777) == "0o444"


def test_prepared_input_symlink_is_rejected_on_reintake(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### misc/X\n- 설명: x\n")
    source = repo / "incoming" / "Demo CTF" / "misc" / "X"
    source.mkdir(parents=True)
    (source / "value.txt").write_text("one")
    record = run_intake(repo)["challenges"][0]
    prepared = Path(record["prepared_input"])
    prepared.chmod(0o755)
    for child in prepared.iterdir():
        child.chmod(0o644)
        child.unlink()
    prepared.rmdir()
    prepared.symlink_to(repo, target_is_directory=True)
    rerun = run_intake(repo)["challenges"][0]
    assert rerun["status"] == "BLOCKED"
    assert "symlink" in rerun["blockers"][0]


def test_archive_traversal_blocks_only_that_challenge(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### misc/A\n### misc/B\n")
    root = repo / "incoming" / "Demo CTF" / "misc"
    root.mkdir()
    with zipfile.ZipFile(root / "A.zip", "w") as archive:
        archive.writestr("../escape", "x")
    (root / "B").mkdir()
    (root / "B" / "ok").write_text("x")
    records = run_intake(repo)["challenges"]
    assert records[0]["status"] == "BLOCKED"
    assert records[1]["status"] == "READY"
    assert not (repo / "escape").exists()


def test_prepare_rejects_source_changes_after_intake(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### misc/X\n- 설명: x\n")
    source = repo / "incoming" / "Demo CTF" / "misc" / "X"
    source.mkdir(parents=True)
    target = source / "value.txt"
    target.write_text("one")
    run_intake(repo)
    target.write_text("changed")
    result = subprocess.run(
        ["python", "-m", "ctf_os.agent_tools", "--repo", str(repo), "prepare-challenge", "1", "--contest", "Demo CTF"],
        capture_output=True, text=True,
    )
    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert "files changed" in payload["error"]


def test_prepare_rejects_tampered_materialized_input(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### misc/X\n- 설명: x\n")
    source = repo / "incoming" / "Demo CTF" / "misc" / "X"
    source.mkdir(parents=True)
    (source / "value.txt").write_text("trusted")
    record = run_intake(repo)["challenges"][0]
    prepared = Path(record["prepared_input"]) / "value.txt"
    prepared.chmod(0o644)
    prepared.write_text("tampered")
    result = subprocess.run(
        ["python", "-m", "ctf_os.agent_tools", "--repo", str(repo), "prepare-challenge", "1", "--contest", "Demo CTF"],
        capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "prepared challenge input changed" in json.loads(result.stdout)["error"]
