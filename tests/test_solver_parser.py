from __future__ import annotations

from ctf_os.flag_detector import FlagDetector
from ctf_os.solver_engine.context import ChallengeContextBuilder
from ctf_os.solver_engine.mock_backend import MockBackend
from ctf_os.solver_engine.parser import ActionObservationParser
from ctf_os.solver_engine.prompt import PromptRenderer
from ctf_os.solver_engine.race_plan import RacePlan


def test_parser_preserves_plan_and_hypothesis_in_order_without_multiline_merging() -> None:
    events = ActionObservationParser().parse(
        "[PLAN] inspect the binary\n"
        "continuation text is not a separate record\n"
        "[HYPOTHESIS] the input reaches a stack buffer\n"
        "[PLAN] compare mitigations before exploiting\n"
        "[FINDING] NX is enabled\n"
        "[FAIL] cyclic offset was wrong\n"
        "[SHIFT] use the saved return address\n"
        "[ARTIFACT] /work/replay.py\n"
        "[FLAG_CANDIDATE] FLAG{REAL_VALUE}\n"
        "[TASK_DONE] replay prepared"
    )

    assert [(event.kind, event.content) for event in events] == [
        ("plan", "inspect the binary"),
        ("hypothesis", "the input reaches a stack buffer"),
        ("plan", "compare mitigations before exploiting"),
        ("finding", "NX is enabled"),
        ("fail", "cyclic offset was wrong"),
        ("shift", "use the saved return address"),
        ("artifact", "/work/replay.py"),
        ("flag_candidate", "FLAG{REAL_VALUE}"),
        ("task_done", "replay prepared"),
    ]
    assert all("\n" not in event.content for event in events)
    assert ActionObservationParser().parse_line("[PLAN] first\n[HYPOTHESIS] second") is None


def test_worker_plan_or_hypothesis_with_flag_like_text_is_not_a_flag_candidate() -> None:
    result = MockBackend([
        "[PLAN] do not treat FLAG{EXAMPLE} as a result",
        "[HYPOTHESIS] a flag may be printed only after verification",
    ]).run("solve")

    assert [(event.kind, event.content) for event in result.events] == [
        ("plan", "do not treat FLAG{EXAMPLE} as a result"),
        ("hypothesis", "a flag may be printed only after verification"),
    ]
    assert all(event.kind != "flag_candidate" for event in result.events)
    assert FlagDetector().detect("[PLAN] do not treat FLAG{EXAMPLE} as a result") == []


def test_existing_findings_context_can_reinject_persisted_plan_and_hypothesis() -> None:
    records = ActionObservationParser().parse(
        "[PLAN] inspect imported symbols\n[HYPOTHESIS] strcmp controls the success path"
    )
    context = ChallengeContextBuilder().build(
        {"id": "rev-check", "category": "rev", "description": "binary"},
        findings=(record.content for record in records),
    )
    prompt = PromptRenderer().render(context, RacePlan.for_score(1).attempts[0])

    assert "- inspect imported symbols" in prompt
    assert "- strcmp controls the success path" in prompt
