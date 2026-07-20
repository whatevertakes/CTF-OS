import json
from pathlib import Path

from ctf_os.flags import matches_flag, verify_and_record


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "output" / "demo" / "misc" / "challenge"
    root.mkdir(parents=True)
    (root / "STATE.json").write_text(json.dumps({"challenge_id": "abc", "status": "PREPARED"}))
    return root


def test_placeholders_and_pattern_mismatch_are_rejected() -> None:
    pattern = r"\ADEMO\{[^}\r\n]+\}\Z"
    assert matches_flag("DEMO{real-value}", pattern)
    assert not matches_flag("DEMO{...}", pattern)
    assert not matches_flag("FLAG{test}", None)
    assert matches_flag("DEMO{contest-winner}", pattern)
    for placeholder in ("FLAG{your_flag_here}", "FLAG{example_flag}", "FLAG{this_is_a_test}", "FLAG{redacted}", "FLAG{TODO}"):
        assert not matches_flag(placeholder, None)


def test_remote_challenge_is_not_ready_without_all_verification(tmp_path: Path) -> None:
    root = _root(tmp_path)
    result = verify_and_record(root, flag="DEMO{real}", pattern=r"\ADEMO\{[^}]+\}\Z", has_remote=True,
                               local_reproduced=True, remote_reproduced=False, independent_rerun=True,
                               reproduce_command="python exploit/solve.py")
    assert not result["ready_for_human_submission"]
    assert json.loads((root / "STATE.json").read_text())["status"] == "VERIFICATION_REQUIRED"


def test_verified_offline_flag_writes_result_and_reproducer(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / "exploit").mkdir()
    (root / "exploit" / "solve.py").write_text("print('DEMO{real}')")
    result = verify_and_record(root, flag="DEMO{real}", pattern=r"\ADEMO\{[^}]+\}\Z", has_remote=False,
                               local_reproduced=True, remote_reproduced=False, independent_rerun=True,
                               reproduce_command="python exploit/solve.py")
    assert not result["ready_for_human_submission"]
    assert (root / "RESULT.md").is_file() and (root / "reproduce.sh").stat().st_mode & 0o111
    assert "ctf_os.agent_tools" in (root / "reproduce.sh").read_text()
    assert "python exploit/solve.py" not in (root / "reproduce.sh").read_text()
    assert json.loads((root / "REPRODUCE.json").read_text())["argv"] == ["python3", "exploit/solve.py"]


def test_strict_verification_requires_distinct_recorded_receipts(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / "exploit").mkdir()
    (root / "exploit" / "solve.py").write_text("print('DEMO{real}')")
    receipts = [
        {"event": "replay_exec", "branch": "local-a", "exit_code": 0, "stdout": "DEMO{real}"},
        {"event": "replay_exec", "branch": "verify-b", "exit_code": 0, "stdout": "DEMO{real}"},
    ]
    (root / "evidence.log").write_text("\n".join(json.dumps(item) for item in receipts) + "\n")
    result = verify_and_record(
        root, flag="DEMO{real}", pattern=r"\ADEMO\{[^}]+\}\Z", has_remote=False,
        local_reproduced=True, remote_reproduced=False, independent_rerun=True,
        reproduce_command="python exploit/solve.py",
        evidence_refs={"local": "local-a", "independent": "verify-b"}, require_recorded_evidence=True,
    )
    assert result["ready_for_human_submission"]
    root2 = _root(tmp_path / "other")
    (root2 / "exploit").mkdir()
    (root2 / "exploit" / "solve.py").write_text("x")
    (root2 / "evidence.log").write_text(json.dumps(receipts[0]) + "\n")
    rejected = verify_and_record(
        root2, flag="DEMO{real}", pattern=r"\ADEMO\{[^}]+\}\Z", has_remote=False,
        local_reproduced=True, remote_reproduced=False, independent_rerun=True,
        reproduce_command="python exploit/solve.py",
        evidence_refs={"local": "local-a", "independent": "local-a"}, require_recorded_evidence=True,
    )
    assert not rejected["ready_for_human_submission"]


def test_strict_receipts_are_input_bound_and_remote_requires_network_observation(tmp_path: Path) -> None:
    root = _root(tmp_path)
    state = json.loads((root / "STATE.json").read_text())
    state["input_fingerprint"] = "new"
    (root / "STATE.json").write_text(json.dumps(state))
    (root / "exploit").mkdir()
    (root / "exploit" / "solve.py").write_text("x")
    stale = [
        {"event": "replay_exec", "branch": "a", "exit_code": 0, "stdout": "DEMO{real}", "input_fingerprint": "old"},
        {"event": "replay_exec", "branch": "b", "exit_code": 0, "stdout": "DEMO{real}", "input_fingerprint": "old"},
    ]
    (root / "evidence.log").write_text("\n".join(json.dumps(item) for item in stale) + "\n")
    stale_result = verify_and_record(
        root, flag="DEMO{real}", pattern=r"\ADEMO\{[^}]+\}\Z", has_remote=False,
        local_reproduced=True, remote_reproduced=False, independent_rerun=True,
        reproduce_command="python exploit/solve.py", evidence_refs={"local": "a", "independent": "b"},
        require_recorded_evidence=True, input_fingerprint="new",
    )
    assert not stale_result["ready_for_human_submission"]

    receipts = [
        {"event": "replay_exec", "branch": "a", "exit_code": 0, "stdout": "DEMO{real}", "input_fingerprint": "new", "authorized_targets": []},
        {"event": "replay_exec", "branch": "b", "exit_code": 0, "stdout": "DEMO{real}", "input_fingerprint": "new", "authorized_targets": []},
        {"event": "replay_exec", "branch": "fake-remote", "command": ["echo", "example.com"], "exit_code": 0, "stdout": "DEMO{real}", "input_fingerprint": "new", "authorized_targets": [{"host": "example.com"}], "authorized_network_observed": False},
    ]
    (root / "evidence.log").write_text("\n".join(json.dumps(item) for item in receipts) + "\n")
    remote_result = verify_and_record(
        root, flag="DEMO{real}", pattern=r"\ADEMO\{[^}]+\}\Z", has_remote=True,
        local_reproduced=True, remote_reproduced=True, independent_rerun=True,
        reproduce_command="python exploit/solve.py",
        evidence_refs={"local": "\"branch\": \"a\"", "independent": "\"branch\": \"b\"", "remote": "fake-remote"},
        require_recorded_evidence=True, input_fingerprint="new", remote_hosts=("example.com",),
    )
    assert not remote_result["ready_for_human_submission"]


def _write_split_receipts(root: Path, *, local: str | None, remote: str | None) -> dict[str, str]:
    receipts = []
    if local is not None:
        receipts.extend([
            {"event": "replay_exec", "receipt_id": "local-one", "exit_code": 0, "stdout": local, "input_fingerprint": "fp"},
            {"event": "replay_exec", "receipt_id": "local-two", "exit_code": 0, "stdout": local, "input_fingerprint": "fp"},
        ])
    receipts.append({
        "event": "replay_exec", "receipt_id": "remote-one", "exit_code": 0,
        "stdout": remote or "remote path reached", "input_fingerprint": "fp",
        "authorized_targets": [{"host": "example.com"}], "authorized_network_observed": True,
    })
    (root / "evidence.log").write_text("\n".join(json.dumps(item) for item in receipts) + "\n")
    state = json.loads((root / "STATE.json").read_text())
    state["input_fingerprint"] = "fp"
    (root / "STATE.json").write_text(json.dumps(state))
    (root / "exploit").mkdir()
    (root / "exploit" / "solve.py").write_text("x")
    return {"local": "local-one", "independent": "local-two", "remote": "remote-one"}


def test_local_dummy_and_remote_real_flag_can_be_fully_verified(tmp_path: Path) -> None:
    root = _root(tmp_path)
    refs = _write_split_receipts(root, local="DEMO{dummy_flag}", remote="DEMO{actual_secret}")
    result = verify_and_record(
        root, flag="DEMO{actual_secret}", pattern=r"\ADEMO\{[^}]+\}\Z", has_remote=True,
        local_reproduced=True, independent_rerun=True, remote_reproduced=True,
        local_success_marker="DEMO{dummy_flag}", remote_flag_candidate="DEMO{actual_secret}",
        exploit_path_matched=True, same_flag_required=False, reproduce_command="python exploit/solve.py",
        evidence_refs=refs, remote_hosts=("example.com",), input_fingerprint="fp",
    )
    assert result["verdict"] == "FULLY_VERIFIED"
    assert not result["ready_for_human_submission"]
    assert result["verification"]["fully_verified"] is True
    assert result["verification"]["same_flag"] is False


def test_explicit_same_flag_policy_and_path_mismatch_prevent_full_verification(tmp_path: Path) -> None:
    for suffix, same_required, path_matched in (("same", True, True), ("path", False, False)):
        root = _root(tmp_path / suffix)
        refs = _write_split_receipts(root, local="DEMO{dummy_flag}", remote="DEMO{actual_secret}")
        result = verify_and_record(
            root, flag="DEMO{actual_secret}", pattern=r"\ADEMO\{[^}]+\}\Z", has_remote=True,
            local_reproduced=True, independent_rerun=True, remote_reproduced=True,
            local_success_marker="DEMO{dummy_flag}", remote_flag_candidate="DEMO{actual_secret}",
            exploit_path_matched=path_matched, same_flag_required=same_required,
            reproduce_command="python exploit/solve.py", evidence_refs=refs,
            remote_hosts=("example.com",), input_fingerprint="fp",
        )
        assert result["verdict"] == "REMOTE_FLAG_OBTAINED"
        assert not result["ready_for_human_submission"]


def test_remote_only_and_local_only_progress_have_distinct_verdicts(tmp_path: Path) -> None:
    remote_root = _root(tmp_path / "remote")
    remote_refs = _write_split_receipts(remote_root, local=None, remote="DEMO{actual_secret}")
    remote = verify_and_record(
        remote_root, flag="DEMO{actual_secret}", pattern=r"\ADEMO\{[^}]+\}\Z", has_remote=True,
        local_reproduced=False, independent_rerun=False, remote_reproduced=True,
        remote_flag_candidate="DEMO{actual_secret}", reproduce_command="python exploit/solve.py",
        evidence_refs=remote_refs, remote_hosts=("example.com",), input_fingerprint="fp",
    )
    assert remote["verdict"] == "REMOTE_FLAG_OBTAINED"

    remote_path_root = _root(tmp_path / "remote-path")
    remote_path_refs = _write_split_receipts(remote_path_root, local=None, remote=None)
    remote_path = verify_and_record(
        remote_path_root, flag="", pattern=r"\ADEMO\{[^}]+\}\Z", has_remote=True,
        local_reproduced=False, independent_rerun=False, remote_reproduced=True,
        reproduce_command="python exploit/solve.py", evidence_refs=remote_path_refs,
        remote_hosts=("example.com",), input_fingerprint="fp",
    )
    assert remote_path["verdict"] == "REMOTE_EXPLOIT_CONFIRMED"

    local_root = _root(tmp_path / "local")
    local_refs = _write_split_receipts(local_root, local="DEMO{dummy_flag}", remote=None)
    local = verify_and_record(
        local_root, flag="DEMO{dummy_flag}", pattern=r"\ADEMO\{[^}]+\}\Z", has_remote=True,
        local_reproduced=True, independent_rerun=True, remote_reproduced=False,
        local_success_marker="DEMO{dummy_flag}", reproduce_command="python exploit/solve.py",
        evidence_refs=local_refs, remote_hosts=("example.com",), input_fingerprint="fp",
    )
    assert local["verdict"] == "LOCAL_EXPLOIT_CONFIRMED"
