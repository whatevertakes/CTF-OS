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


def test_admin_reintake_detects_changes_without_mutating_solve_workspace(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### misc/X\n- 설명: x\n")
    source = repo / "incoming" / "Demo CTF" / "misc" / "X"
    source.mkdir(parents=True)
    (source / "value.txt").write_text("one")
    prepared = _prepare(repo)
    assert prepared.returncode == 0
    prepared_payload = json.loads(prepared.stdout)["result"]
    solve_root = Path(prepared_payload["solve_root"])
    run_root = Path(prepared_payload["run_root"])
    (run_root / "RESULT.md").write_text("keep me")
    state_before = (run_root / "STATE.json").read_bytes()
    input_before = (solve_root / "input" / "value.txt").read_bytes()
    (source / "value.txt").write_text("two")
    admin = run_intake(repo)["challenges"][0]
    admin_root = Path(admin["workspace_path"])

    assert admin_root != solve_root
    assert admin_root.parts[-3] == "admin-intake"
    assert (admin_root / "input" / "value.txt").read_text() == "two"
    assert oct((admin_root / "input" / "value.txt").stat().st_mode & 0o777) == "0o444"
    assert (run_root / "RESULT.md").read_text() == "keep me"
    assert (run_root / "STATE.json").read_bytes() == state_before
    assert (solve_root / "input" / "value.txt").read_bytes() == input_before
    assert not list(solve_root.glob("RESULT.stale-*.md"))


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


def _prepare(
    repo: Path, contest: str = "Demo CTF", selector: str = "1",
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python", "-m", "ctf_os.agent_tools", "--repo", str(repo), "prepare-challenge", selector, "--contest", contest],
        capture_output=True, text=True,
    )


def test_prepare_bootstraps_challenge_local_preflight_in_the_same_call(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### misc/X\n- 설명: x\n")
    source = repo / "incoming" / "Demo CTF" / "misc" / "X"
    source.mkdir(parents=True)
    (source / "value.txt").write_text("one")

    result = _prepare(repo)

    assert result.returncode == 0
    payload = json.loads(result.stdout)["result"]
    solve_root = Path(payload["solve_root"])
    run_root = Path(payload["run_root"])
    preflight_path = Path(payload["preflight_record_path"])
    preflight = json.loads(preflight_path.read_text())
    launch = payload["solve_launch_context"]
    launch_path = Path(payload["solve_launch_path"])
    assert launch["schema_version"] == 1
    assert launch["challenge_id"] == payload["challenge"]["id"]
    assert launch["challenge_key"] == payload["challenge"]["key"]
    assert launch["input_fingerprint"] == preflight["source_fingerprint"]
    assert launch["objective"] == "FIRST_VALID_FLAG"
    assert launch["problem_information"]["description"] == "x"
    assert "contest_triage" not in launch
    assert not list((repo / "output").glob("*/intake.json"))
    assert launch["execution_policy"]["same_session_required"] is True
    assert launch["execution_policy"]["maximum_active_hypotheses"] == 3
    assert launch_path == solve_root / "SOLVE-LAUNCH.json"
    assert preflight_path == solve_root / "CHALLENGE-PREFLIGHT.json"
    assert json.loads(launch_path.read_text()) == launch
    first_launch = launch_path.read_bytes()
    assert (solve_root / "input" / "value.txt").read_text() == "one"
    assert (run_root / "evidence.log").read_text() == ""
    assert not (run_root / "findings.jsonl").exists()
    assert (run_root / "race-events.jsonl").read_text() == ""
    assert "dedicated Sol session" not in result.stdout

    repeated = _prepare(repo)
    assert repeated.returncode == 0
    assert launch_path.read_bytes() == first_launch


def test_prepare_bootstraps_directly_from_user_problems_file(repo: Path) -> None:
    contest = repo / "incoming" / "Demo CTF"
    contest.mkdir()
    (contest / "problems.txt").write_text(
        "대회명: Demo CTF\n\nmisc/X\n설명: user supplied problem\n",
        encoding="utf-8",
    )
    source = contest / "misc" / "X"
    source.mkdir(parents=True)
    (source / "value.txt").write_text("one")

    result = _prepare(repo)

    assert result.returncode == 0
    assert (contest / "contest.md").is_file()
    assert not list((repo / "output").glob("*/intake.json"))
    payload = json.loads(result.stdout)["result"]
    assert Path(payload["preflight_record_path"]).is_file()


def test_solve_launch_includes_declared_target_and_priority_file(repo: Path) -> None:
    write_contest(repo, """# Demo CTF
### web/X
- Description: remote app
- Remote: nc example.com 31337
""")
    source = repo / "incoming" / "Demo CTF" / "web" / "X"
    source.mkdir(parents=True)
    (source / "app.py").write_text("print('ready')\n")

    result = _prepare(repo)
    assert result.returncode == 0
    launch = json.loads(result.stdout)["result"]["solve_launch_context"]
    assert launch["authorized_targets"][0]["host"] == "example.com"
    assert launch["authorized_targets"][0]["port"] == 31337
    assert launch["authorized_targets"][0]["protocol"] == "tcp"
    assert any(item["path"] == "app.py" for item in launch["priority_files"])
    assert launch["important_metadata"]["file_count"] == 1
    assert launch["important_metadata"]["total_size"] > 0


def test_prepare_repairs_selected_source_changes_without_rewriting_intake(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### misc/X\n- 설명: x\n")
    source = repo / "incoming" / "Demo CTF" / "misc" / "X"
    source.mkdir(parents=True)
    target = source / "value.txt"
    target.write_text("one")
    first = _prepare(repo)
    assert first.returncode == 0
    first_payload = json.loads(first.stdout)["result"]
    preflight_path = Path(first_payload["preflight_record_path"])
    old_fingerprint = json.loads(preflight_path.read_text())["source_fingerprint"]
    target.write_text("changed")
    result = _prepare(repo)
    payload = json.loads(result.stdout)["result"]
    refreshed = json.loads(preflight_path.read_text())
    assert result.returncode == 0
    assert refreshed["source_fingerprint"] != old_fingerprint
    assert not list((repo / "output").glob("*/intake.json"))
    assert (Path(payload["solve_root"]) / "input" / "value.txt").read_text() == "changed"


def test_prepare_repairs_tampered_materialized_input(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### misc/X\n- 설명: x\n")
    source = repo / "incoming" / "Demo CTF" / "misc" / "X"
    source.mkdir(parents=True)
    (source / "value.txt").write_text("trusted")
    first = _prepare(repo)
    assert first.returncode == 0
    prepared = Path(json.loads(first.stdout)["result"]["solve_root"]) / "input" / "value.txt"
    prepared.chmod(0o644)
    prepared.write_text("tampered")
    result = _prepare(repo)
    assert result.returncode == 0
    assert prepared.read_text() == "trusted"


def test_prepare_repairs_deleted_materialized_input(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### misc/X\n- 설명: x\n")
    source = repo / "incoming" / "Demo CTF" / "misc" / "X"
    source.mkdir(parents=True)
    (source / "value.txt").write_text("trusted")
    first = _prepare(repo)
    assert first.returncode == 0
    prepared = Path(json.loads(first.stdout)["result"]["solve_root"]) / "input"
    prepared.chmod(0o755)
    for child in prepared.iterdir():
        child.chmod(0o644)
        child.unlink()
    prepared.rmdir()

    result = _prepare(repo)

    assert result.returncode == 0
    assert (prepared / "value.txt").read_text() == "trusted"


def test_unrelated_contest_metadata_does_not_stale_selected_challenge(repo: Path) -> None:
    manifest_path = write_contest(
        repo, "# Demo CTF\n- Date: 2026-07-20\n### misc/X\n- Description: x\n",
    )
    source = repo / "incoming" / "Demo CTF" / "misc" / "X"
    source.mkdir(parents=True)
    (source / "value.txt").write_text("trusted")
    first = _prepare(repo)
    assert first.returncode == 0
    preflight_path = Path(json.loads(first.stdout)["result"]["preflight_record_path"])
    before = preflight_path.read_bytes()
    manifest_path.write_text(
        "# Demo CTF\n- Date: 2026-07-21\n### misc/X\n- Description: x\n",
    )

    result = _prepare(repo)

    assert result.returncode == 0
    assert preflight_path.read_bytes() == before


def test_selected_description_change_refreshes_local_preflight(repo: Path) -> None:
    manifest_path = write_contest(repo, "# Demo CTF\n### misc/X\n- Description: before\n")
    source = repo / "incoming" / "Demo CTF" / "misc" / "X"
    source.mkdir(parents=True)
    (source / "value.txt").write_text("trusted")
    first = _prepare(repo)
    assert first.returncode == 0
    preflight_path = Path(json.loads(first.stdout)["result"]["preflight_record_path"])
    old = json.loads(preflight_path.read_text())
    manifest_path.write_text("# Demo CTF\n### misc/X\n- Description: after\n")

    result = _prepare(repo)

    assert result.returncode == 0
    refreshed = json.loads(preflight_path.read_text())
    assert refreshed["challenge"]["description"] == "after"
    assert refreshed["source_fingerprint"] != old["source_fingerprint"]


def test_prepare_syncs_changed_problem_description_before_local_preflight(repo: Path) -> None:
    contest = repo / "incoming" / "Demo CTF"
    contest.mkdir()
    problems = contest / "problems.txt"
    problems.write_text("대회명: Demo CTF\n\nmisc/X\n설명: before\n", encoding="utf-8")
    source = contest / "misc" / "X"
    source.mkdir(parents=True)
    (source / "value.txt").write_text("trusted")
    assert _prepare(repo).returncode == 0
    problems.write_text("대회명: Demo CTF\n\nmisc/X\n설명: after\n", encoding="utf-8")

    result = _prepare(repo)

    assert result.returncode == 0
    payload = json.loads(result.stdout)["result"]
    preflight = json.loads(Path(payload["preflight_record_path"]).read_text())
    assert preflight["challenge"]["description"] == "after"


def test_prepare_repairs_corrupt_selected_preflight_record(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### misc/X\n- Description: x\n")
    source = repo / "incoming" / "Demo CTF" / "misc" / "X"
    source.mkdir(parents=True)
    (source / "value.txt").write_text("trusted")
    first = _prepare(repo)
    assert first.returncode == 0
    preflight_path = Path(json.loads(first.stdout)["result"]["preflight_record_path"])
    preflight_path.write_text("{broken")

    result = _prepare(repo)

    assert result.returncode == 0
    repaired = json.loads(preflight_path.read_text())
    assert repaired["status"] == "READY"
    assert repaired["challenge"]["key"] == "misc/X"

    repaired["priority_files"] = {"not": "a list"}
    preflight_path.write_text(json.dumps(repaired))
    second = _prepare(repo)
    assert second.returncode == 0
    assert isinstance(json.loads(preflight_path.read_text())["priority_files"], list)


def test_prepare_reports_selected_challenge_blocker_without_session_handoff(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### misc/Missing\n- Description: required file is absent\n")

    result = _prepare(repo)
    error = json.loads(result.stdout)["error"]

    assert result.returncode == 2
    assert "The selected challenge remains BLOCKED" in error
    assert "no matching directory/archive" in error
    assert "dedicated Sol session" not in error
    assert "triage-finalize" not in error


def test_prepare_does_not_read_or_rewrite_symlink_legacy_intake_index(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### misc/X\n- Description: x\n")
    source = repo / "incoming" / "Demo CTF" / "misc" / "X"
    source.mkdir(parents=True)
    (source / "value.txt").write_text("trusted")
    first = _prepare(repo)
    assert first.returncode == 0
    solve_root = Path(json.loads(first.stdout)["result"]["solve_root"])
    index_path = solve_root.parents[1] / "intake.json"
    backup = repo / "outside-intake.json"
    backup.write_text('{"legacy": true}')
    index_path.symlink_to(backup)
    before = backup.read_bytes()

    result = _prepare(repo)

    assert result.returncode == 0
    assert index_path.is_symlink()
    assert backup.read_bytes() == before


def test_prepare_repairs_tampered_preflight_prepared_input_path(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### misc/X\n- Description: x\n")
    source = repo / "incoming" / "Demo CTF" / "misc" / "X"
    source.mkdir(parents=True)
    (source / "value.txt").write_text("trusted")
    first = _prepare(repo)
    assert first.returncode == 0
    payload = json.loads(first.stdout)["result"]
    preflight_path = Path(payload["preflight_record_path"])
    preflight = json.loads(preflight_path.read_text())
    preflight["prepared_input"] = str(repo / "outside")
    preflight_path.write_text(json.dumps(preflight))

    result = _prepare(repo)

    assert result.returncode == 0
    repaired = json.loads(preflight_path.read_text())
    assert Path(repaired["prepared_input"]) == Path(payload["solve_root"]) / "input"


def test_prepare_rejects_symlink_local_preflight_record(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### misc/X\n- Description: x\n")
    source = repo / "incoming" / "Demo CTF" / "misc" / "X"
    source.mkdir(parents=True)
    (source / "value.txt").write_text("trusted")
    first = _prepare(repo)
    assert first.returncode == 0
    preflight_path = Path(json.loads(first.stdout)["result"]["preflight_record_path"])
    outside = repo / "outside-preflight.json"
    outside.write_text(preflight_path.read_text())
    preflight_path.unlink()
    preflight_path.symlink_to(outside)

    result = _prepare(repo)

    assert result.returncode == 2
    assert "generated path is unsafe" in json.loads(result.stdout)["error"]


def test_prepare_rejects_symlink_solve_launch_file(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### misc/X\n- Description: x\n")
    source = repo / "incoming" / "Demo CTF" / "misc" / "X"
    source.mkdir(parents=True)
    (source / "value.txt").write_text("trusted")
    first = _prepare(repo)
    assert first.returncode == 0
    launch_path = Path(json.loads(first.stdout)["result"]["solve_launch_path"])
    outside = repo / "outside-launch.json"
    outside.write_text('{"outside": true}')
    launch_path.unlink()
    launch_path.symlink_to(outside)

    result = _prepare(repo)

    assert result.returncode == 2
    assert "Solve Launch Context path must not be a symlink" in json.loads(result.stdout)["error"]
    assert outside.read_text() == '{"outside": true}'


def test_solve_launch_refresh_preserves_terminal_state_and_flag_receipt(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### misc/X\n- Description: x\n")
    source = repo / "incoming" / "Demo CTF" / "misc" / "X"
    source.mkdir(parents=True)
    (source / "value.txt").write_text("trusted")
    first = _prepare(repo)
    assert first.returncode == 0
    first_payload = json.loads(first.stdout)["result"]
    solve_root = Path(first_payload["solve_root"])
    run_root = Path(first_payload["run_root"])
    state_path = run_root / "STATE.json"
    state = json.loads(state_path.read_text())
    state.update({
        "status": "SUBMISSION_RECOMMENDED",
        "flag_candidate": "DEMO{preserve}",
        "submission_recommended": True,
        "remote_flag_receipt": "flag-receipts/remote-preserve.json",
    })
    state_path.write_text(json.dumps(state, sort_keys=True))
    receipt = run_root / "flag-receipts" / "remote-preserve.json"
    receipt.parent.mkdir(exist_ok=True)
    receipt.write_text('{"flag": "DEMO{preserve}"}')
    artifact = run_root / "artifacts" / "solve.py"
    artifact.parent.mkdir()
    artifact.write_text("print('preserve')")
    evidence = run_root / "evidence.log"
    evidence.write_text("preserve evidence\n")
    worker = run_root / "workers" / "race-1" / "result.json"
    worker.parent.mkdir(parents=True)
    worker.write_text('{"result": "preserve"}')
    state_bytes = state_path.read_bytes()
    receipt_bytes = receipt.read_bytes()
    artifact_bytes = artifact.read_bytes()
    evidence_bytes = evidence.read_bytes()
    worker_bytes = worker.read_bytes()

    result = _prepare(repo)

    assert result.returncode == 0
    assert (solve_root / "SOLVE-LAUNCH.json").is_file()
    assert state_path.read_bytes() == state_bytes
    assert receipt.read_bytes() == receipt_bytes
    assert artifact.read_bytes() == artifact_bytes
    assert evidence.read_bytes() == evidence_bytes
    assert worker.read_bytes() == worker_bytes


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


def test_intake_recommends_new_category_images_and_file_signal_overrides(repo: Path) -> None:
    write_contest(repo, """# Demo CTF
### osint/domain-clue
### ai/model
### cloud/chart
### misc/apk-in-disguise
""")
    fixtures = {
        ("osint", "domain-clue", "clue.txt"): "public domain and map clue",
        ("ai", "model", "network.onnx"): "model",
        ("cloud", "chart", "Chart.yaml"): "apiVersion: v2",
        ("misc", "apk-in-disguise", "challenge.apk"): "apk",
    }
    for (category, name, filename), content in fixtures.items():
        path = repo / "incoming" / "Demo CTF" / category / name
        path.mkdir(parents=True)
        (path / filename).write_text(content)
    records = run_intake(repo)["challenges"]
    assert [record["recommended_profile"] for record in records] == ["osint", "ai", "cloud", "rev"]
    assert records[1]["recommended_image"] == "ctf-os-sandbox:ai"
    assert "ONNX Runtime" in records[1]["recommended_tools"]
    assert "jadx" in records[3]["recommended_tools"]


def test_intake_marks_kvm_and_gpu_as_needs_review(repo: Path) -> None:
    write_contest(repo, "# Demo CTF\n### ai/accelerated\n")
    source = repo / "incoming" / "Demo CTF" / "ai" / "accelerated"
    source.mkdir(parents=True)
    (source / "README.txt").write_text("CUDA GPU required and /dev/kvm")
    record = run_intake(repo)["challenges"][0]
    assert record["needs_review"] is True
    assert len(record["special_permission_requirement"]) == 2
