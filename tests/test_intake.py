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


def test_intake_builds_detailed_safe_compose_plan_and_compact_context(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### web/App\n- Description: app\n")
    source = repo / "incoming" / "Demo CTF" / "web" / "App"
    source.mkdir(parents=True)
    (source / "compose.yml").write_text("""
services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
      args: {MODE: release}
    ports: ["8081:8080"]
    environment: {MODE: ctf}
    healthcheck: {test: [CMD, curl, -f, http://localhost:8080/]}
    depends_on: [db]
    command: [python3, app.py]
    volumes: ["./data:/app/data:ro"]
  db:
    image: redis:7-alpine
""", encoding="utf-8")
    (source / "Dockerfile").write_text("FROM python:3.12-slim\nEXPOSE 8080\n", encoding="utf-8")
    (source / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (source / "data").mkdir()
    for number in range(25):
        (source / "data" / f"f{number:02d}.txt").write_text(str(number), encoding="utf-8")
    record = run_intake(repo)["challenges"][0]
    plan = record["service_plan"]
    assert record["containerized_challenge"] is True
    assert plan["kind"] == "compose" and plan["safe_to_start"] is True
    app = next(service for service in plan["services"] if service["name"] == "app")
    assert app["build_context"] == "."
    assert app["mapped_ports"][0]["published"] == 8081
    assert app["internal_target"] == "http://app:8080"
    assert app["environment"] == {"MODE": "ctf"}
    assert next(service for service in plan["services"] if service["name"] == "db")["external_image_pull"] is True
    assert record["recommended_image"] == "ctf-os-sandbox:web"
    assert record["recommended_resource_profile"] == "standard"
    assert len(record["priority_files"]) == 20
    inventory = json.loads(Path(record["inventory_path"]).read_text())
    assert len(inventory["files"]) == 28
    context = Path(record["context_path"]).read_text()
    assert "Full inventory:" in context and "Priority files (top 20)" in context


def test_intake_marks_dangerous_compose_needs_review(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### web/Danger\n- Description: app\n")
    source = repo / "incoming" / "Demo CTF" / "web" / "Danger"
    source.mkdir(parents=True)
    (source / "compose.yaml").write_text("""
services:
  app:
    image: example.invalid/chall:latest
    privileged: true
    network_mode: host
    pid: host
    ipc: host
    cap_add: [SYS_ADMIN]
    devices: [/dev/kvm:/dev/kvm]
    volumes:
      - /:/host
      - /var/run/docker.sock:/var/run/docker.sock
""", encoding="utf-8")
    record = run_intake(repo)["challenges"][0]
    plan = record["service_plan"]
    assert plan["safe_to_start"] is False
    reasons = "\n".join(plan["review_reasons"])
    for expected in ("privileged", "host network", "host PID", "host IPC", "device", "capabilities", "host root", "Docker socket"):
        assert expected in reasons


def test_dockerfile_plan_and_manifest_warnings_are_visible(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### pwn/Service\n- Remtoe: nc example.test 31337\n")
    source = repo / "incoming" / "Demo CTF" / "pwn" / "Service"
    source.mkdir(parents=True)
    (source / "Dockerfile").write_text("""FROM debian:stable-slim
ARG PORT=31337
ENV MODE=ctf
EXPOSE 31337/tcp
ENTRYPOINT [\"/chall\"]
HEALTHCHECK CMD nc -z localhost 31337
""", encoding="utf-8")
    payload = run_intake(repo)
    record = payload["challenges"][0]
    assert record["service_plan"]["kind"] == "dockerfile"
    assert record["service_plan"]["services"][0]["internal_target"] == "chall:31337"
    assert record["warnings"][0]["suggestion"] == "remote"
    intake_markdown = (repo / "output" / payload["contest"]["slug"] / "INTAKE.md").read_text()
    assert "Manifest warning: **HIGH**" in intake_markdown
