import json
from dataclasses import replace
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


def test_contract_defaults_same_flag_policy_to_false_and_validates_it(tmp_path: Path) -> None:
    _repo, _manifest, _challenge_value, root, _record = _workspace(tmp_path)
    assert load_contract(root, "fingerprint")["same_flag_required"] is False
    contract = json.loads((root / "REPRODUCE.json").read_text())
    contract["same_flag_required"] = "no"
    (root / "REPRODUCE.json").write_text(json.dumps(contract))
    with pytest.raises(ReplayError, match="same_flag_required"):
        load_contract(root, "fingerprint")


def test_contract_accepts_an_explicit_local_success_marker_pattern(tmp_path: Path) -> None:
    _repo, _manifest, _challenge_value, root, _record = _workspace(tmp_path)
    contract = json.loads((root / "REPRODUCE.json").read_text())
    contract["local_success_pattern"] = r"EXPLOIT_OK:[a-z]+"
    (root / "REPRODUCE.json").write_text(json.dumps(contract))
    assert load_contract(root, "fingerprint")["local_success_pattern"] == r"EXPLOIT_OK:[a-z]+"


def test_solver_artifact_fingerprint_tracks_content_and_rejects_links(tmp_path: Path) -> None:
    exploit = tmp_path / "exploit"
    exploit.mkdir()
    solver = exploit / "solve.py"
    solver.write_text("print('one')\n")
    first = replay._solver_fingerprint(exploit)
    solver.write_text("print('two')\n")
    assert replay._solver_fingerprint(exploit) != first
    (exploit / "linked.py").symlink_to(solver)
    with pytest.raises(ReplayError, match="link or special"):
        replay._solver_fingerprint(exploit)


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


def test_remote_replay_keeps_local_marker_and_remote_flag_separate(monkeypatch, tmp_path: Path) -> None:
    repo, manifest, challenge, root, record = _workspace(tmp_path)
    challenge = replace(challenge, remotes=("https://example.com",))
    manifest = replace(manifest, challenges=(challenge,))

    def fake_create(spec, docker="docker"):
        spec.branch_root.mkdir(parents=True, exist_ok=True)
        targets = [{"host": target.host} for target in spec.targets]
        return {
            "name": f"ctf-os-{spec.branch}", "branch": spec.branch,
            "branch_root": str(spec.branch_root), "authorized_targets": targets,
            "input_fingerprint": "fingerprint", "labels": spec.labels,
        }

    def fake_execute(metadata, argv, timeout, docker="docker"):
        remote = metadata["branch"] == "replay-remote"
        return {
            "command": argv, "exit_code": 0, "timed_out": False,
            "stdout": "DEMO{actual_secret}\n" if remote else "DEMO{dummy_flag}\n",
            "stderr": "", "authorized_targets": metadata["authorized_targets"],
            "authorized_network_observed": remote, "input_fingerprint": "fingerprint",
        }

    monkeypatch.setattr(replay, "resolve_targets", lambda targets: targets)
    monkeypatch.setattr(replay, "create", fake_create)
    monkeypatch.setattr(replay, "stage_artifacts", lambda *args, **kwargs: {"files": 1})
    monkeypatch.setattr(replay, "execute", fake_execute)
    monkeypatch.setattr(replay, "cleanup", lambda metadata, **kwargs: {"removed": True, "container": metadata["name"]})

    result = run_replay(repo, manifest, challenge, record)

    assert result["local_success_marker"] == "DEMO{dummy_flag}"
    assert result["remote_flag_candidate"] == "DEMO{actual_secret}"
    assert result["flag_candidate"] == "DEMO{actual_secret}"
    assert result["verdict"] == "FULLY_VERIFIED"


def test_remote_exit_zero_without_flag_or_success_marker_is_not_confirmed(monkeypatch, tmp_path: Path) -> None:
    repo, manifest, challenge, root, record = _workspace(tmp_path)
    challenge = replace(challenge, remotes=("https://example.com",))
    manifest = replace(manifest, challenges=(challenge,))

    def fake_create(spec, docker="docker"):
        spec.branch_root.mkdir(parents=True, exist_ok=True)
        return {
            "name": f"ctf-os-{spec.branch}", "branch": spec.branch,
            "branch_root": str(spec.branch_root),
            "authorized_targets": [{"host": target.host} for target in spec.targets],
            "input_fingerprint": "fingerprint", "labels": spec.labels,
        }

    def fake_execute(metadata, argv, timeout, docker="docker"):
        remote = metadata["branch"] == "replay-remote"
        return {
            "command": argv, "exit_code": 0, "timed_out": False,
            "stdout": "request completed\n" if remote else "DEMO{dummy_flag}\n",
            "stderr": "", "authorized_targets": metadata["authorized_targets"],
            "authorized_network_observed": remote, "input_fingerprint": "fingerprint",
        }

    monkeypatch.setattr(replay, "resolve_targets", lambda targets: targets)
    monkeypatch.setattr(replay, "create", fake_create)
    monkeypatch.setattr(replay, "stage_artifacts", lambda *args, **kwargs: {"files": 1})
    monkeypatch.setattr(replay, "execute", fake_execute)
    monkeypatch.setattr(replay, "cleanup", lambda metadata, **kwargs: {"removed": True})

    result = run_replay(repo, manifest, challenge, record)

    assert result["verdict"] == "LOCAL_EXPLOIT_CONFIRMED"
    assert result["verification"]["verification"]["remote_exploit_confirmed"] is False
