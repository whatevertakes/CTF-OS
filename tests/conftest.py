from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ctf_os.contest import parse_contest
from ctf_os.preflight import input_fingerprint, prepare_input
from ctf_os.race import initialize_race, mark_root_ready
from ctf_os.workspace import create_run, utc_now


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "incoming").mkdir()
    (tmp_path / "output").mkdir()
    return tmp_path


def write_challenge(
    repo: Path,
    *,
    contest: str = "Demo CTF",
    category: str = "web",
    name: str = "Example",
    remote: str | None = None,
    flag_pattern: str = r"\ACTF\{[^}\r\n]+\}\Z",
    files: dict[str, bytes] | None = None,
) -> tuple[Any, Any]:
    root = repo / "incoming" / contest
    root.mkdir(parents=True)
    remote_line = f"- remote: {remote}\n" if remote else ""
    (root / "contest.md").write_text(
        f"# Contest: {contest}\n- flag_pattern: {flag_pattern}\n\n"
        f"### {category}/{name}\n- description: one challenge\n{remote_line}",
        encoding="utf-8",
    )
    if files is not None:
        challenge_root = root / category / name
        challenge_root.mkdir(parents=True)
        for relative, content in files.items():
            path = challenge_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    manifest = parse_contest(root / "contest.md")
    return manifest, manifest.challenges[0]


def fake_sandbox(run: Path, challenge: Any, lane_id: str, image: str = "ctf-os-sandbox:web") -> dict[str, Any]:
    lane_root = run / "workers" / lane_id
    for name in ("work", "evidence", "artifacts", "logs", "context", "sessions"):
        (lane_root / name).mkdir(parents=True, exist_ok=True)
    metadata_path = lane_root / "sandbox.json"
    value = {
        "schema_version": 1,
        "status": "READY",
        "name": f"ctf-os-{run.name}-{lane_id}".lower(),
        "run_id": run.name,
        "challenge_id": challenge.id,
        "category": challenge.category,
        "lane_id": lane_id,
        "image": image,
        "source": str(run / "input"),
        "lane_root": str(lane_root),
        "metadata_path": str(metadata_path),
        "input_fingerprint": "0" * 64,
        "labels": {"org.ctf-os.kind": "sandbox"},
        "target_identities": [f"challenge:{challenge.id}"],
        "paths": {
            "input": "/challenge", "work": "/work", "evidence": "/evidence",
            "artifacts": "/artifacts", "host_work": str(lane_root / "work"),
            "host_evidence": str(lane_root / "evidence"),
            "host_artifacts": str(lane_root / "artifacts"),
        },
        "created_at": utc_now(),
        "exec_command_prefix": ["uv", "run", "python", "-m", "ctf_os.agent_tools", "sandbox-exec", "--metadata", str(metadata_path), "--"],
    }
    metadata_path.write_text(__import__("json").dumps(value), encoding="utf-8")
    return value


def make_race(
    repo: Path,
    *,
    category: str = "web",
    remote: str | None = None,
    root_model_profile: str = "sol-ultra",
    root_model_profile_source: str = "policy-default",
):
    manifest, challenge = write_challenge(
        repo, category=category, remote=remote, files={"app.py": b"print('hello')\n"}
    )
    fingerprint = input_fingerprint(manifest, challenge)
    selected = utc_now()
    run, run_manifest = create_run(repo, manifest, challenge, input_fingerprint=fingerprint, now=selected)
    input_record = prepare_input(manifest, challenge, run, expected_fingerprint=fingerprint)
    race = initialize_race(
        run,
        run_manifest=run_manifest,
        input_record=input_record,
        image={"selected_image": f"ctf-os-sandbox:{category}", "status": "AVAILABLE"},
        service={"network": None, "endpoints": []},
        selected_at=selected,
        input_ready_at=utc_now(),
        root_model_profile=root_model_profile,
        root_model_profile_source=root_model_profile_source,
    )
    root = fake_sandbox(run, challenge, "root", f"ctf-os-sandbox:{category}")
    race = mark_root_ready(run, root)
    return manifest, challenge, run, race
