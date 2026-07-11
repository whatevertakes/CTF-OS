from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ctf_os.artifact_writer import ArtifactWriter
from ctf_os.contest_parser import ContestParseError, filter_challenges, parse_contest
from ctf_os.flag_detector import FlagDetector, is_placeholder
from ctf_os.local_state import LocalState, StateTransitionError
from ctf_os.models import Attempt, Challenge, ChallengeStatus, Event, FlagCandidate


def _manifest(tmp_path):
    path = tmp_path / "incoming" / "sca" / "contest.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """# 대회명: SCA CTF 2026

## 대회 정보
- 날짜: 2026-07-19
- 플래그 형식: SCA{...}
- 플래그 패턴: SCA\\{[A-Z0-9_]+\\}
- 팀: 지웅팀

## 문제 목록

### web/sqli
- 점수: 100
- 원격: http://web.sca.kr:8080
- 설명: 로그인 우회
- 힌트: quote handling

### pwn/bof
- 점수: 300
- 원격: nc pwn.sca.kr 1234
- 설명: 스택 기반 버퍼 오버플로우
""",
        encoding="utf-8",
    )
    return path


def test_contest_parser_metadata_stable_ids_and_owned_filter(tmp_path):
    manifest = parse_contest(_manifest(tmp_path))
    assert manifest.name == "SCA CTF 2026"
    assert manifest.flag_patterns == (r"SCA\{[A-Z0-9_]+\}",)
    web = manifest.challenges[0]
    assert (web.category, web.name, web.score, web.remote, web.hint) == (
        "web", "sqli", 100, "http://web.sca.kr:8080", "quote handling",
    )
    assert web.id.startswith("chal_") and web.slug == "web-sqli"
    assert web.id == parse_contest(_manifest(tmp_path)).challenges[0].id
    assert [challenge.name for challenge in filter_challenges(manifest.challenges, ["PWN", "misc"])] == ["bof"]


def test_owned_filter_uses_same_common_aliases_as_solver_planning() -> None:
    challenges = [
        Challenge(contest="Demo", category="binary exploitation", name="bof"),
        Challenge(contest="Demo", category="reverse engineering", name="keygen"),
        Challenge(contest="Demo", category="stego", name="pixels"),
    ]
    assert [item.name for item in filter_challenges(challenges, ["pwn", "rev", "forensics"])] == [
        "bof", "keygen", "pixels"
    ]


@pytest.mark.parametrize("heading", ["### web/..", "### web/one/two", "### ../sqli"])
def test_contest_parser_rejects_unsafe_challenge_paths(tmp_path, heading):
    path = tmp_path / "contest.md"
    path.write_text(f"# 대회명: test\n\n{heading}\n- 점수: 1\n", encoding="utf-8")
    with pytest.raises(ContestParseError):
        parse_contest(path)


@pytest.mark.parametrize(
    ("headings", "message"),
    [
        (("web/a-b", "web/a b"), "identifier collision"),
        (("web/a-b", "web-a/b"), "workspace collision"),
    ],
)
def test_contest_parser_rejects_normalized_identifier_collisions(tmp_path, headings, message):
    path = tmp_path / "contest.md"
    sections = "\n\n".join(f"### {heading}\n- 점수: 1" for heading in headings)
    path.write_text(f"# 대회명: test\n\n{sections}\n", encoding="utf-8")

    with pytest.raises(ContestParseError, match=message):
        parse_contest(path)


def test_local_state_upsert_transitions_attempt_events_and_candidates(tmp_path, claimed_attempt):
    state = LocalState(tmp_path / "output" / "local_state.db")
    challenge = Challenge(contest="SCA", category="web", name="sqli", score=100, description="old")
    inserted = state.upsert_challenge(challenge)
    state.transition_challenge_status(inserted.id, ChallengeStatus.QUEUED)
    attempt = claimed_attempt(state, inserted, owner="owner-a", attempt_id="attempt-a")
    state.transition_challenge_status(
        inserted.id,
        ChallengeStatus.RUNNING,
        attempt_id=attempt.id,
        owner=attempt.lease_owner,
        fencing_token=attempt.fencing_token,
    )

    reparsed = state.upsert_challenge(Challenge(contest="SCA", category="web", name="sqli", score=200, description="new"))
    assert reparsed.id == inserted.id
    assert (reparsed.status, reparsed.score, reparsed.description) == (ChallengeStatus.RUNNING, 200, "new")
    with pytest.raises(StateTransitionError):
        state.transition_challenge_status(inserted.id, ChallengeStatus.SOLVED)

    assert state.get_attempt(attempt.id) == attempt
    event = Event(team_id="team", member="member", contest="SCA", type="FINDING", challenge_id=inserted.id, attempt_id=attempt.id, payload={"x": 1})
    state.append_event(event)
    assert state.list_events(challenge_id=inserted.id)[0].payload == {"x": 1}
    candidate = FlagCandidate(challenge_id=inserted.id, attempt_id=attempt.id, value="SCA{REAL_FLAG}", confidence=0.9)
    state.add_flag_candidate(candidate)
    assert state.list_flag_candidates(inserted.id) == [candidate]


def test_flag_detector_prioritizes_custom_patterns_and_filters_placeholders():
    detector = FlagDetector([r"CUSTOM\[[^\]]+\]"])
    values = detector.detect("CUSTOM[good] SCA{fake_flag} SCA{REAL_1} FLAG{example}")
    assert values == ["CUSTOM[good]", "SCA{REAL_1}"]
    assert is_placeholder("SCA{...}")
    assert is_placeholder("FLAG{demo_flag}")
    candidates = detector.detect_candidates("SCA{REAL_1}", challenge_id="chal")
    assert candidates[0].value == "SCA{REAL_1}" and not candidates[0].verified


def test_artifact_writer_creates_tree_and_appends_notes_and_evidence(tmp_path):
    challenge = Challenge(contest="SCA CTF", category="web", name="sqli")
    writer = ArtifactWriter(tmp_path / "output", "SCA CTF")
    root = writer.prepare_challenge(challenge)
    assert root == tmp_path / "output" / "SCA CTF" / "web-sqli"
    assert (root / "final").is_dir() and (root / "attempts").is_dir()
    writer.append_evidence(challenge, "stdout flag candidate")
    writer.append_note(challenge, "finding", "possible SQL injection")
    work = writer.attempt_dir(challenge, "abc", profile="recon_fast")
    writer.write_final_exploit(challenge, "print('ok')\n")
    writer.write_replay(challenge, "#!/bin/sh\n")
    assert work == root / "attempts" / "recon_fast-abc"
    assert (work / "work").is_dir()
    assert "stdout flag candidate" in (root / "evidence.log").read_text(encoding="utf-8")
    assert "FINDING" in (root / "notes.md").read_text(encoding="utf-8")
    assert (root / "final" / "exploit.py").read_text(encoding="utf-8") == "print('ok')\n"
