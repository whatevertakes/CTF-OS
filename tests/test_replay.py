import json
from pathlib import Path

import pytest

from ctf_os.contest import ChallengeSpec, ContestManifest
from ctf_os.replay import ReplayError, load_contract, run_replay
import ctf_os.replay as replay


def _challenge() -> ChallengeSpec:
    return ChallengeSpec(
        number=1, id="abc123", category="misc", name="Toy", workspace_name="toy",
        score=None, description=None, hint=None, remotes=(), flag_format="DEMO{...}",
        flag_pattern=r"\ADEMO\{[^}\r\n]+\}\Z", input_profile="standard",
    )


def _workspace(tmp_path: Path):
    repo = tmp_path
    manifest_path = repo / "incoming" / "demo" / "contest.md"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text("# Demo\n### misc/Toy\n")
    challenge = _challenge()
    manifest = ContestManifest(
        name="Demo", slug="demo", path=manifest_path, date=None,
        flag_format="DEMO{...}", flag_pattern=challenge.flag_pattern,
        input_profile="standard", challenges=(challenge,),
    )
    root = repo / "output" / "demo" / "misc" / "toy"
    (root / "input").mkdir(parents=True)
    (root / "exploit").mkdir()
    (root / "exploit" / "solve.py").write_text("print('DEMO{real}')")
    (root / "STATE.json").write_text(json.dumps({"challenge_id": challenge.id, "status": "PREPARED", "input_fingerprint": "fingerprint"}))
    (root / "REPRODUCE.json").write_text(json.dumps({
        "schema_version": 1, "image_profile": "base", "resource_profile": "light",
        "service_required": False, "argv": ["python3", "/artifacts/exploit/solve.py"],
        "expected_flag_pattern": challenge.flag_pattern, "input_fingerprint": "fingerprint",
    }))
    record = {"workspace_path": str(root), "source_fingerprint": "fingerprint", "service_plan": {"kind": "none"}}
    return repo, manifest, challenge, root, record


def test_contract_rejects_stale_fingerprint(tmp_path: Path) -> None:
    _repo, _manifest, _challenge_value, root, _record = _workspace(tmp_path)
    with pytest.raises(ReplayError, match="stale"):
        load_contract(root, "changed")


def test_offline_replay_uses_two_clean_sandboxes_and_records_ready(monkeypatch, tmp_path: Path) -> None:
    repo, manifest, challenge, root, record = _workspace(tmp_path)
    created = []

    def fake_create(spec, docker="docker"):
        created.append(spec)
        spec.branch_root.mkdir(parents=True, exist_ok=True)
        return {
            "name": f"ctf-os-{spec.branch}", "branch": spec.branch,
            "branch_root": str(spec.branch_root), "authorized_targets": [],
            "input_fingerprint": "fingerprint", "labels": spec.labels,
        }

    monkeypatch.setattr(replay, "create", fake_create)
    monkeypatch.setattr(replay, "stage_artifacts", lambda *args, **kwargs: {"files": 1})
    monkeypatch.setattr(replay, "execute", lambda *args, **kwargs: {
        "command": args[1], "exit_code": 0, "timed_out": False,
        "stdout": "DEMO{real}\n", "stderr": "", "authorized_targets": [],
        "authorized_network_observed": False, "input_fingerprint": "fingerprint",
    })
    monkeypatch.setattr(replay, "cleanup", lambda metadata, **kwargs: {"removed": True, "container": metadata["name"]})

    result = run_replay(repo, manifest, challenge, record)

    assert result["flag_candidate"] == "DEMO{real}"
    assert len(created) == 2 and all(spec.branch.startswith("replay-local-") for spec in created)
    assert result["verification"]["status"] == "READY_FOR_HUMAN_SUBMISSION"
    assert "ctf_os.agent_tools" in (root / "reproduce.sh").read_text()
    assert json.loads((root / "STATE.json").read_text())["status"] == "READY_FOR_HUMAN_SUBMISSION"
