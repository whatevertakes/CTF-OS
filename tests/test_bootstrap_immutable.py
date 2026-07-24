"""H1 regression: bootstrap uses immutable run state, not the mutable manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest
from conftest import fake_sandbox, make_race
from test_blackboard_race import _receipt
from test_race_bootstrap import _spec

import ctf_os.agent_tools.__main__ as cli
from ctf_os.race import note_command_receipt
from ctf_os.sandbox.network import ResolvedTarget


def _bootstrap_env(repo: Path, monkeypatch):
    manifest, challenge, run, _race = make_race(repo, remote="nc ctf.example 31337")
    note_command_receipt(
        run, _receipt(run, challenge, "root", "root attack", receipt_id="root-first")
    )

    captured: dict[str, object] = {}

    def fake_create(spec, docker="docker"):
        captured.setdefault("targets", []).append(list(spec.targets))
        captured["category"] = spec.category
        captured["contest_slug"] = spec.contest_slug
        return fake_sandbox(run, challenge, spec.lane_id, spec.image)

    def fake_resolve(targets, blocked_gateways=frozenset()):
        return tuple(ResolvedTarget(target, "203.0.113.5") for target in targets)

    monkeypatch.setattr(cli, "create", fake_create)
    monkeypatch.setattr(cli, "collect_docker_gateways", lambda docker="docker": frozenset())
    monkeypatch.setattr(cli, "resolve_targets", fake_resolve)
    return manifest, challenge, run, captured


def test_bootstrap_passes_preparation_time_target_after_manifest_swap(
    repo: Path, monkeypatch
) -> None:
    manifest, _challenge, _run, captured = _bootstrap_env(repo, monkeypatch)

    # Swap the manifest remote AND category after preparation.
    manifest_path = Path(manifest.path)
    manifest_path.write_text(
        "# Contest: Demo CTF\n- flag_pattern: \\ACTF\\{[^}\\r\\n]+\\}\\Z\n\n"
        "### web/Example\n- description: one challenge\n- remote: nc evil.example 1337\n",
        encoding="utf-8",
    )

    result = cli._race_bootstrap(
        repo,
        argparse.Namespace(
            selector="1", contest="Demo CTF",
            lanes_json=json.dumps([_spec("source-dataflow")]),
            lanes_file=None, docker="docker",
        ),
    )
    assert result["failures"] == []
    lane_targets = captured["targets"][0]
    # The child must see the preparation-time target, never the swapped one.
    assert lane_targets[0].target.host == "ctf.example"
    assert all(t.target.host != "evil.example" for t in lane_targets)
    assert captured["category"] == "web"


def test_bootstrap_identifies_active_run_after_challenge_removed(
    repo: Path, monkeypatch
) -> None:
    manifest, _challenge, _run, _captured = _bootstrap_env(repo, monkeypatch)

    # Remove the challenge heading entirely from the manifest.
    Path(manifest.path).write_text(
        "# Contest: Demo CTF\n- flag_pattern: \\ACTF\\{[^}\\r\\n]+\\}\\Z\n",
        encoding="utf-8",
    )

    result = cli._race_bootstrap(
        repo,
        argparse.Namespace(
            selector="1", contest="Demo CTF",
            lanes_json=json.dumps([_spec("still-works")]),
            lanes_file=None, docker="docker",
        ),
    )
    assert result["failures"] == []
    assert len(result["packets"]) == 1


def test_bootstrap_rejects_selector_not_matching_active_run(
    repo: Path, monkeypatch
) -> None:
    _manifest, _challenge, _run, _captured = _bootstrap_env(repo, monkeypatch)
    with pytest.raises(ValueError, match="does not match the exact active race"):
        cli._race_bootstrap(
            repo,
            argparse.Namespace(
                selector="7", contest="Demo CTF",
                lanes_json=json.dumps([_spec("wrong-selector")]),
                lanes_file=None, docker="docker",
            ),
        )
