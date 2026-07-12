from __future__ import annotations

from pathlib import Path
from threading import Event
import stat
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest
import yaml

from ctf_os.application import IntakeBlockedError, LocalApplication, PrerequisiteError, RunReport
from ctf_os.config import AppConfig, default_config_mapping
from ctf_os.local_state import LocalState
from ctf_os.watcher import PathPollingWatcher


def _config(tmp_path: Path, *, category: str = "web") -> AppConfig:
    raw = default_config_mapping("Demo")
    raw["member"]["owned_categories"] = [category]
    raw["sandbox"]["enabled"] = False
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return AppConfig.from_file(path)


def _manifest(tmp_path: Path, category: str, *, remote: str = "") -> None:
    path = tmp_path / "incoming" / "Demo" / "contest.md"
    path.parent.mkdir(parents=True)
    path.write_text(
        f"# 대회명: Demo\n\n### {category}/sample\n- 설명: authorized challenge\n- 원격: {remote}\n",
        encoding="utf-8",
    )


def test_plain_challenge_directory_is_materialized_once(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _manifest(tmp_path, "web")
    source = tmp_path / "incoming" / "Demo" / "web" / "sample"
    source.mkdir(parents=True)
    (source / "app.py").write_text("print('ok')\n", encoding="utf-8")

    item = LocalApplication(config).parse()[0]
    copied = item.workspace / "app.py"
    first_inode = copied.stat().st_ino
    assert copied.read_text(encoding="utf-8") == "print('ok')\n"

    LocalApplication(config).parse()
    assert copied.stat().st_ino == first_inode


def test_plain_challenge_directory_rejects_symlinks(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _manifest(tmp_path, "web")
    source = tmp_path / "incoming" / "Demo" / "web" / "sample"
    source.mkdir(parents=True)
    (source / "escape").symlink_to(tmp_path / "outside")

    assert LocalApplication(config).parse() == ()
    state = LocalState.for_config(config)
    challenge = state.list_challenges()[0]
    assert challenge.status.value == "INTAKE_BLOCKED"
    assert "symlink blocked" in state.list_events()[-1].message


def test_forensic_and_forensics_share_one_source_layout(tmp_path: Path) -> None:
    config = _config(tmp_path, category="forensic")
    _manifest(tmp_path, "forensics")
    source = tmp_path / "incoming" / "Demo" / "forensic" / "sample"
    source.mkdir(parents=True)
    (source / "image.raw").write_bytes(b"evidence")

    item = LocalApplication(config).parse()[0]
    assert (item.workspace / "image.raw").read_bytes() == b"evidence"


def test_path_watcher_detects_plain_files_and_empty_directories(tmp_path: Path) -> None:
    root = tmp_path / "incoming"
    root.mkdir()
    watcher = PathPollingWatcher((root,), include=lambda path: "workspace" not in path.parts)
    assert watcher.changed()

    source = root / "Demo" / "web" / "sample"
    source.mkdir(parents=True)
    assert watcher.changed()
    (source / "chall").write_bytes(b"ELF")
    assert watcher.changed()

    workspace = root / "Demo" / "workspace" / "sample"
    workspace.mkdir(parents=True)
    watcher.acknowledge()
    (workspace / "generated").write_text("copy", encoding="utf-8")
    assert not watcher.changed()


def test_path_watcher_acknowledges_handler_owned_state_write(tmp_path: Path) -> None:
    state = tmp_path / "local_state.db"
    state.write_bytes(b"before")
    watcher = PathPollingWatcher((state,))
    assert watcher.changed()
    state.write_bytes(b"after")
    watcher.acknowledge()
    assert not watcher.changed()


def test_watch_recovers_from_transient_intake_block(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = _config(tmp_path)
    stop = Event()

    class DeterministicWatcher:
        def __init__(self, *_args, **_kwargs) -> None:
            self.polls = 0
            self.acknowledged = 0

        def changed(self) -> bool:
            return True

        def acknowledge(self) -> None:
            self.acknowledged += 1

        def wait(self, _stop: Event) -> bool:
            self.polls += 1
            if self.polls == 2:
                stop.set()
            return True

    watcher = DeterministicWatcher()
    monkeypatch.setattr("ctf_os.application.PathPollingWatcher", lambda *_args, **_kwargs: watcher)
    app = LocalApplication(config)
    calls = 0

    def run_once(**_kwargs) -> RunReport:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise IntakeBlockedError("queue blocked: partial contest.md")
        return RunReport(parsed_challenges=1, started_attempts=0, solved_challenges=0, synthetic=False)

    monkeypatch.setattr(app, "run_once", run_once)
    assert app.run(stop_event=stop) is None
    assert calls == 2
    assert watcher.acknowledged == 2


def test_watch_does_not_acknowledge_input_changes_that_arrive_during_a_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    stop = Event()

    class DeterministicWatcher:
        def __init__(self, *, input_watcher: bool) -> None:
            self.input_watcher = input_watcher
            self.polls = 0
            self.acknowledged = 0

        def changed(self) -> bool:
            # The second input change represents a challenge file arriving
            # while the first bounded run was still executing.
            return self.input_watcher

        def acknowledge(self) -> None:
            self.acknowledged += 1

        def wait(self, _stop: Event) -> bool:
            self.polls += 1
            if self.input_watcher and self.polls == 2:
                stop.set()
            return True

    input_watcher = DeterministicWatcher(input_watcher=True)
    state_watcher = DeterministicWatcher(input_watcher=False)
    watchers = iter((input_watcher, state_watcher))
    monkeypatch.setattr("ctf_os.application.PathPollingWatcher", lambda *_args, **_kwargs: next(watchers))
    app = LocalApplication(config)
    calls = 0

    def run_once(**_kwargs) -> RunReport:
        nonlocal calls
        calls += 1
        return RunReport(parsed_challenges=1, started_attempts=0, solved_challenges=0, synthetic=False)

    monkeypatch.setattr(app, "run_once", run_once)
    assert app.run(stop_event=stop) is None
    assert calls == 2
    assert input_watcher.acknowledged == 0
    assert state_watcher.acknowledged == 2


def test_ready_challenge_without_matching_source_or_remote_is_blocked(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _manifest(tmp_path, "web")
    misplaced = tmp_path / "incoming" / "Demo" / "web" / "different-name.zip"
    misplaced.parent.mkdir(parents=True)
    with ZipFile(misplaced, "w") as bundle:
        bundle.writestr("app.py", "pass\n")

    with pytest.raises(PrerequisiteError, match=r"no matching source or valid remote.*path/name.*mismatch"):
        LocalApplication(config).parse()


def test_valid_remote_only_challenge_can_queue_without_attachment(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _manifest(tmp_path, "web", remote="nc challenge.example 31337")

    item = LocalApplication(config).parse()[0]

    assert item.archives == ()
    assert list(item.workspace.iterdir()) == []


@pytest.mark.parametrize("name", ["sample.7z", "sample.tar.gz", "web-sample.tgz"])
def test_matching_non_zip_archive_is_handed_to_sandbox_workspace(tmp_path: Path, name: str) -> None:
    config = _config(tmp_path)
    _manifest(tmp_path, "web")
    attachment = tmp_path / "incoming" / "Demo" / "web" / name
    attachment.parent.mkdir(parents=True)
    attachment.write_bytes(b"not silently ignored")

    item = LocalApplication(config).parse()[0]

    assert item.attachments == (attachment,)
    assert (item.workspace / name).read_bytes() == b"not silently ignored"


def test_competition_zip_policy_accepts_legitimate_high_compression(tmp_path: Path) -> None:
    raw = default_config_mapping("Demo")
    raw["member"]["owned_categories"] = ["web"]
    raw["sandbox"]["enabled"] = False
    raw["intake"]["zip_limits"]["max_compression_ratio"] = 100_000
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    config = AppConfig.from_file(path)
    _manifest(tmp_path, "web")
    archive = tmp_path / "incoming" / "Demo" / "web" / "sample.zip"
    archive.parent.mkdir(parents=True)
    with ZipFile(archive, "w", ZIP_DEFLATED) as bundle:
        bundle.writestr("large-zero-filled-image.raw", b"\0" * (2 * 1024 * 1024))

    item = LocalApplication(config).parse()[0]

    assert (item.workspace / "large-zero-filled-image.raw").stat().st_size == 2 * 1024 * 1024


def test_operator_can_lower_zip_policy_per_contest(tmp_path: Path) -> None:
    raw = default_config_mapping("Demo")
    raw["member"]["owned_categories"] = ["web"]
    raw["sandbox"]["enabled"] = False
    raw["intake"]["zip_limits"]["max_total_bytes"] = 16
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    config = AppConfig.from_file(path)
    _manifest(tmp_path, "web")
    archive = tmp_path / "incoming" / "Demo" / "web" / "sample.zip"
    archive.parent.mkdir(parents=True)
    with ZipFile(archive, "w") as bundle:
        bundle.writestr("payload", b"A" * 17)

    assert LocalApplication(config).parse() == ()
    state = LocalState.for_config(config)
    assert state.list_challenges()[0].status.value == "INTAKE_BLOCKED"
    assert "total expanded-byte limit" in state.list_events()[-1].message


def test_blocked_zip_is_isolated_and_normal_sibling_still_queues(tmp_path: Path) -> None:
    config = _config(tmp_path)
    manifest = tmp_path / "incoming" / "Demo" / "contest.md"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        "# 대회명: Demo\n\n### web/panopticon\n- 설명: OVMF package\n\n"
        "### web/healthy\n- 설명: independent source\n",
        encoding="utf-8",
    )
    archive = manifest.parent / "web" / "panopticon.zip"
    archive.parent.mkdir(parents=True)
    with ZipFile(archive, "w", ZIP_DEFLATED) as bundle:
        bundle.writestr("deploy/OVMF_VARS.fd", b"\0" * 540_672)
    healthy = manifest.parent / "web" / "healthy"
    healthy.mkdir()
    (healthy / "app.py").write_text("print('ready')\n", encoding="utf-8")

    ready = LocalApplication(config).parse()
    state = LocalState.for_config(config)
    challenges = {item.name: item for item in state.list_challenges()}

    assert [item.challenge.name for item in ready] == ["healthy"]
    assert challenges["panopticon"].status.value == "INTAKE_BLOCKED"
    assert challenges["healthy"].status.value == "QUEUED"
    blocked = [event for event in state.list_events() if event.type == "INTAKE_BLOCKED"]
    assert blocked[-1].payload["code"] == "ZIP_COMPRESSION_RATIO_LIMIT"
    assert blocked[-1].payload["member"] == "deploy/OVMF_VARS.fd"


def test_uppercase_zip_and_unix_executable_bit_are_preserved(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _manifest(tmp_path, "web")
    archive = tmp_path / "incoming" / "Demo" / "web" / "sample.ZIP"
    archive.parent.mkdir(parents=True)
    executable = ZipInfo("run.sh")
    executable.create_system = 3
    executable.external_attr = (stat.S_IFREG | 0o755) << 16
    with ZipFile(archive, "w") as bundle:
        bundle.writestr(executable, "#!/bin/sh\nexit 0\n")

    item = LocalApplication(config).parse()[0]

    assert item.archives == (archive,)
    assert item.workspace.joinpath("run.sh").stat().st_mode & 0o111


def test_encrypted_zip_is_normalized_to_intake_error(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _manifest(tmp_path, "web")
    archive = tmp_path / "incoming" / "Demo" / "web" / "sample.zip"
    archive.parent.mkdir(parents=True)
    with ZipFile(archive, "w") as bundle:
        bundle.writestr("secret.txt", "ciphertext")
    data = bytearray(archive.read_bytes())
    local = data.index(b"PK\x03\x04")
    central = data.index(b"PK\x01\x02")
    data[local + 6:local + 8] = (1).to_bytes(2, "little")
    data[central + 8:central + 10] = (1).to_bytes(2, "little")
    archive.write_bytes(data)

    assert LocalApplication(config).parse() == ()
    state = LocalState.for_config(config)
    assert state.list_challenges()[0].status.value == "INTAKE_BLOCKED"
    assert "encrypted ZIP members are unsupported" in state.list_events()[-1].message
