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
