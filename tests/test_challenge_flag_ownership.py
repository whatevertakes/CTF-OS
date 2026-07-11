from __future__ import annotations

from dataclasses import replace

from ctf_os.flag_detector import FlagDetector
from ctf_os.local_state import LocalState
from ctf_os.local_event_state import LocalEventState
from ctf_os.models import Attempt, Challenge, Event, FlagCandidate


def _challenge(state: LocalState, *, contest: str, category: str, name: str, team: str = "team") -> Challenge:
    challenge = Challenge(contest=contest, category=category, name=name)
    challenge = replace(challenge, challenge_key=f"{team}:{challenge.challenge_key}")
    return state.upsert_challenge(challenge)


def _attempt(state: LocalState, challenge: Challenge, attempt_id: str) -> None:
    state.upsert_attempt(Attempt(
        id=attempt_id, challenge_id=challenge.id, profile="test", role="test",
        backend="mock", workdir=f"/tmp/{attempt_id}",
    ))


def test_flags_are_bound_to_correct_challenge(tmp_path):
    state = LocalState(tmp_path / "state.db")
    a = _challenge(state, contest="Demo", category="pwn", name="bof")
    b = _challenge(state, contest="Demo", category="web", name="sqli")
    detector = FlagDetector()

    candidates_a = detector.detect_candidates(
        "SCA{bof_real}", challenge_id=a.id, challenge_key=a.challenge_key,
        attempt_id="attempt-a", source="codex-stream",
    )
    candidates_b = detector.detect_candidates(
        "SCA{sqli_real}", challenge_id=b.id, challenge_key=b.challenge_key,
        attempt_id="attempt-b", source="codex-stream",
    )
    _attempt(state, a, "attempt-a")
    _attempt(state, b, "attempt-b")
    state.add_flag_candidate(candidates_a[0])
    state.add_flag_candidate(candidates_b[0])

    assert [(item.value, item.attempt_id) for item in state.list_flag_candidates(a.id)] == [("SCA{bof_real}", "attempt-a")]
    assert [(item.value, item.attempt_id) for item in state.list_flag_candidates(b.id)] == [("SCA{sqli_real}", "attempt-b")]


def test_duplicate_challenge_names_do_not_cross_update(tmp_path):
    state = LocalState(tmp_path / "state.db")
    pwn = _challenge(state, contest="Demo", category="pwn", name="bof")
    rev = _challenge(state, contest="Demo", category="rev", name="bof")
    _attempt(state, pwn, "a")
    state.add_flag_candidate(FlagCandidate(
        challenge_id=pwn.id, challenge_key=pwn.challenge_key, value="SCA{owned}", attempt_id="a",
    ))
    assert [item.value for item in state.list_flag_candidates(pwn.id)] == ["SCA{owned}"]
    assert state.list_flag_candidates(rev.id) == []


def test_same_flag_value_can_exist_for_different_challenges(tmp_path):
    state = LocalState(tmp_path / "state.db")
    a = _challenge(state, contest="Demo", category="pwn", name="one")
    b = _challenge(state, contest="Demo", category="web", name="two")
    for challenge in (a, b):
        _attempt(state, challenge, f"attempt-{challenge.id}")
        state.add_flag_candidate(FlagCandidate(
            challenge_id=challenge.id, challenge_key=challenge.challenge_key,
            value="SCA{same}", attempt_id=f"attempt-{challenge.id}",
        ))
    assert state.list_flag_candidates(a.id)[0].challenge_id == a.id
    assert state.list_flag_candidates(b.id)[0].challenge_id == b.id


def test_local_events_map_by_challenge_key_and_not_flag_value():
    events = [
        Event(team_id="team", member="alice", contest="Demo", type="SOLVED",
              challenge_id="foreign-a", challenge_key="team:demo:pwn:bof", category="pwn", challenge="bof",
              payload={"flag": "SCA{same}", "verified": True}),
        Event(team_id="team", member="bob", contest="Demo", type="SOLVED",
              challenge_id="foreign-b", challenge_key="team:demo:web:bof", category="web", challenge="bof",
              payload={"flag": "SCA{same}", "verified": True}),
    ]
    merged = LocalEventState.from_events(events)
    assert merged.get("team:demo:pwn:bof").events == (events[0],)
    assert merged.get("team:demo:web:bof").events == (events[1],)


def test_flag_ownership_survives_restart(tmp_path):
    path = tmp_path / "state.db"
    state = LocalState(path)
    challenge = _challenge(state, contest="Demo", category="pwn", name="persist")
    _attempt(state, challenge, "attempt-persist")
    state.add_flag_candidate(FlagCandidate(
        challenge_id=challenge.id, challenge_key=challenge.challenge_key,
        value="SCA{persisted}", attempt_id="attempt-persist",
    ))
    reopened = LocalState(path)
    restored = reopened.list_flag_candidates(challenge.id)[0]
    assert (restored.challenge_id, restored.challenge_key, restored.value) == (
        challenge.id, challenge.challenge_key, "SCA{persisted}",
    )
