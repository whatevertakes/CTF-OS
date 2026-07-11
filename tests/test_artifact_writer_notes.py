from __future__ import annotations

from ctf_os.artifact_writer import ArtifactWriter
from ctf_os.models import Challenge
from ctf_os.solver_engine.parser import ActionObservationParser


def test_promoted_records_keep_plan_hypothesis_labels_duplicates_and_arrival_order(tmp_path) -> None:
    challenge = Challenge(contest="Demo", category="web", name="login")
    writer = ArtifactWriter(tmp_path / "output", "Demo")
    staging = writer.create_attempt_staging()
    records = ActionObservationParser().parse(
        "[PLAN] enumerate routes\n"
        "[HYPOTHESIS] debug mode exposes a stack trace\n"
        "[PLAN] compare the unauthenticated endpoints\n"
        "[FINDING] /debug returns source paths\n"
        "[FAIL] /admin is protected\n"
        "[SHIFT] inspect error handling"
    )

    try:
        writer.promote_attempt_observations(
            challenge,
            attempt_workdir=staging.workdir,
            records=records,
        )
    finally:
        ArtifactWriter.cleanup_attempt_staging(staging.workdir)

    notes = (writer.challenge_dir(challenge) / "notes.md").read_text(encoding="utf-8")
    headings = [line.split(" — ", 1)[0] for line in notes.splitlines() if line.startswith("## ")]
    assert headings == ["## PLAN", "## HYPOTHESIS", "## PLAN", "## FINDING", "## FAIL", "## SHIFT"]
    assert notes.count("## PLAN —") == 2
    assert "enumerate routes" in notes
    assert "debug mode exposes a stack trace" in notes


def test_parent_approved_branch_artifacts_are_snapshotted_as_handoff(tmp_path) -> None:
    challenge = Challenge(contest="Demo", category="pwn", name="rop")
    writer = ArtifactWriter(tmp_path / "output", "Demo")
    staging = writer.create_attempt_staging()
    replay = staging.artifacts / "replay.sh"
    replay.write_text("#!/bin/sh\necho reproduced\n", encoding="utf-8")
    try:
        assert writer.promote_session_handoff_artifacts(
            challenge, session_id="s1", contract_id="A", attempt_workdir=staging.workdir,
            artifact_paths=[replay], parent_approved=False,
        ) == ()
        promoted = writer.promote_session_handoff_artifacts(
            challenge, session_id="s1", contract_id="A", attempt_workdir=staging.workdir,
            artifact_paths=[replay], parent_approved=True,
        )
        assert len(promoted) == 1
        assert promoted[0].read_text(encoding="utf-8").endswith("reproduced\n")
        assert "/handoff/s1/A/" in str(promoted[0])
    finally:
        ArtifactWriter.cleanup_attempt_staging(staging.workdir)


def test_approved_handoff_is_seeded_into_a_fresh_isolated_branch(tmp_path) -> None:
    challenge = Challenge(contest="Demo", category="crypto", name="solver")
    writer = ArtifactWriter(tmp_path / "output", "Demo")
    source = writer.create_attempt_staging()
    target = writer.create_attempt_staging()
    solver = source.workdir / "solver.py"
    solver.write_text("print('reused')\n", encoding="utf-8")
    try:
        writer.promote_session_handoff_artifacts(
            challenge, session_id="session_1", contract_id="task_A",
            attempt_workdir=source.workdir, artifact_paths=[solver], parent_approved=True,
        )
        seeded = writer.seed_session_handoff_artifacts(
            challenge, session_id="session_1", attempt_workdir=target.workdir,
        )
        assert seeded == ("/work/handoff/task_A/solver.py",)
        assert (target.workdir / "handoff" / "task_A" / "solver.py").read_text(
            encoding="utf-8"
        ) == "print('reused')\n"
    finally:
        ArtifactWriter.cleanup_attempt_staging(source.workdir)
        ArtifactWriter.cleanup_attempt_staging(target.workdir)
