from __future__ import annotations

from ctf_os.solver_engine.context import ChallengeContextBuilder
from ctf_os.solver_engine.knowledge import KnowledgeChunk, KnowledgeIndex, PlaybookSelector
from ctf_os.solver_engine.loop_detector import LoopDetector
from ctf_os.solver_engine.mock_backend import MockBackend
from ctf_os.solver_engine.parser import ActionObservationParser
from ctf_os.solver_engine.prompt import PromptRenderer
from ctf_os.solver_engine.race_plan import RacePlan
from ctf_os.solver_engine.verifier import Verifier


def _context():
    return ChallengeContextBuilder().build(
        {
            "id": "web-login",
            "title": "Login",
            "category": "web",
            "score": 300,
            "description": "Find the bug in the login form.",
            "remotes": ["https://ctf.example:8443"],
        },
        files=["/workspace/app.py"],
        findings=["username looks interpolated"],
        failed_strategies=["basic SQLi in password field"],
        failed_commands=["ctf-exec curl -i https://ctf.example:8443/login"],
    )


def test_race_plan_profiles_limits_and_unique_ids() -> None:
    easy = RacePlan.for_score(200)
    medium = RacePlan.for_score(400)
    hard = RacePlan.for_score(500)

    assert [attempt.profile.name for attempt in easy.attempts] == ["recon_fast", "exploit_fast"]
    assert [attempt.profile.max_runtime_sec for attempt in medium.attempts] == [300, 1200, 1200]
    assert [attempt.profile.name for attempt in hard.attempts] == ["recon_deep", "source_deep", "exploit_main", "exploit_alt", "fallback"]
    assert len({attempt.attempt_id for attempt in hard.attempts}) == len(hard.attempts)
    assert len({attempt.strategy_seed for attempt in hard.attempts}) == len(hard.attempts)


def test_prompt_is_diverse_injects_shared_records_and_has_safety_invariants() -> None:
    plan = RacePlan.for_score(300, category="web", id_factory=lambda: "attempt", seed_factory=lambda: "seed")
    main, alt = plan.attempts[1:]
    main_prompt = PromptRenderer().render(_context(), main)
    alt_prompt = PromptRenderer().render(_context(), alt)

    assert main_prompt != alt_prompt
    assert "curl/browser requests" in main_prompt
    assert "disjoint vulnerability class" in alt_prompt
    assert "username looks interpolated" in alt_prompt
    assert "independently validate before use" in alt_prompt
    assert "ctf-exec curl" in alt_prompt
    assert "https://ctf.example:8443" in alt_prompt
    assert "Only connect to remotes explicitly listed in contest.md" in alt_prompt
    assert "Do not access credentials, SSH keys, browser data, API keys, or personal files." in alt_prompt
    assert "Do not write outside /work and /artifacts." in alt_prompt
    assert all(f"[{tag}]" in alt_prompt for tag in ("PLAN", "HYPOTHESIS", "ACTION", "OBSERVATION", "FINDING", "FAIL", "SHIFT", "FLAG_CANDIDATE", "ARTIFACT", "TASK_DONE"))


def test_category_plans_produce_distinct_executable_algorithms_and_aliases() -> None:
    pwn = RacePlan.for_score(300, category="binary exploitation").attempts[1]
    crypto = RacePlan.for_score(300, category="cryptography").attempts[1]
    web = RacePlan.for_score(300, category="web").attempts[1]

    assert pwn.category == "pwn" and "pwntools" in pwn.strategy_instruction
    assert crypto.category == "crypto" and "Python/Sage/Z3" in crypto.strategy_instruction
    assert web.category == "web" and "curl/browser" in web.strategy_instruction
    assert len({pwn.strategy_instruction, crypto.strategy_instruction, web.strategy_instruction}) == 3


def test_every_category_attempt_is_self_contained_and_has_category_verification() -> None:
    expected = {
        "pwn": "clean local process",
        "rev": "original binary",
        "crypto": "round-trip",
        "web": "clean reproducible session",
        "forensics": "independent parser",
        "cloud": "effective permission",
        "misc": "end-to-end solver",
    }
    for category, verification in expected.items():
        plan = RacePlan.for_score(500, category=category)
        assert all("self-contained solve attempt" in item.strategy_instruction for item in plan.attempts)
        assert all(verification in item.strategy_instruction for item in plan.attempts)


def test_compatibility_build_preserves_category() -> None:
    plan = RacePlan.build(300, category="reverse engineering")
    assert all(item.category == "rev" for item in plan.attempts)


def test_tag_parser_keeps_structured_external_records_including_plan_and_hypothesis() -> None:
    events = ActionObservationParser().parse(
        "[PLAN] silently reason about it\n[HYPOTHESIS] maybe x\n[ACTION] ctf-exec file /workspace/chall\n[OBSERVATION] ELF 64-bit\n[FINDING] no PIE\n[FAIL] payload failed"
    )

    assert [(event.kind, event.content) for event in events] == [
        ("plan", "silently reason about it"),
        ("hypothesis", "maybe x"),
        ("action", "ctf-exec file /workspace/chall"),
        ("observation", "ELF 64-bit"),
        ("finding", "no PIE"),
        ("fail", "payload failed"),
    ]


def test_loop_detector_emits_shift_for_repeated_commands_and_failures() -> None:
    detector = LoopDetector()

    assert not detector.observe_command("ctf-exec file /workspace/chall").shift_required
    command_shift = detector.observe_command("ctf-exec   file /workspace/chall")
    failure_shift = detector.observe_failure("connection refused")
    failure_shift = detector.observe_failure(" CONNECTION refused ")

    assert command_shift.shift_required and "repeated command" in command_shift.reason
    assert failure_shift.shift_required and "repeated failure" in failure_shift.reason


def test_knowledge_retrieval_category_filter_and_playbook_selection() -> None:
    index = KnowledgeIndex()
    try:
        index.index(
            [
                KnowledgeChunk("web-ssti", "knowledge/playbooks/web.md", "web", "Use template probes for server-side template injection.", ("SSTI",), ("curl",)),
                KnowledgeChunk("pwn-rop", "knowledge/playbooks/pwn.md", "pwn", "Use checksec before a ROP chain.", ("ROP",), ("gdb",)),
            ]
        )
        results = index.retrieve("template injection", category="web")

        assert [chunk.id for chunk in results] == ["web-ssti"]
        assert PlaybookSelector().select("unknown-category") == "misc"
        assert PlaybookSelector().select("PWN") == "pwn"
    finally:
        index.close()


def test_verifier_keeps_candidate_and_verified_separate_and_rejects_placeholders() -> None:
    verifier = Verifier()

    candidate = verifier.candidate("got FLAG{real_value}")
    verified = verifier.verify("got FLAG{real_value}")
    solved = verifier.verify("got FLAG{real_value}", replay_succeeded=True)

    assert candidate.state == "candidate"
    assert verified.state == "verified"
    assert solved.state == "verified"
    assert verifier.candidate("FLAG{...}").state == "rejected"
    assert verifier.candidate("FLAG{demo_flag}").state == "rejected"


def test_mock_backend_streams_deterministically_and_parses_external_events() -> None:
    streamed = []
    raw_output = []
    backend = MockBackend(["[PLAN] private", "[ACTION] ctf-exec file /workspace/chall", "[OBSERVATION] ELF"])

    result = backend.run("prompt", on_event=streamed.append, on_output=raw_output.append)

    assert backend.prompts == ["prompt"]
    assert result.status == "completed"
    assert [event.kind for event in result.events] == ["plan", "action", "observation"]
    assert [event.kind for event in streamed] == ["plan", "action", "observation"]
    assert raw_output == ["[PLAN] private", "[ACTION] ctf-exec file /workspace/chall", "[OBSERVATION] ELF"]
