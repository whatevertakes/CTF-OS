from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from threading import Thread

from textual.widgets import DataTable, Static

from ctf_os.config import AppConfig, default_config_mapping
from ctf_os.local_state import LocalState
from ctf_os.local_event_state import LocalEventState
from ctf_os.models import Attempt, Challenge, ChallengeStatus, Event, FlagCandidate
from ctf_os.tui import CTFOSDashboard, challenge_view


def _config(tmp_path) -> AppConfig:
    return AppConfig(default_config_mapping("Demo"), tmp_path / "config.yaml")


def _challenge(state: LocalState, category: str, name: str) -> Challenge:
    value = Challenge(contest="Demo", category=category, name=name)
    return state.upsert_challenge(replace(value, challenge_key=f"demo-team:{value.challenge_key}"))


def _attempt(state: LocalState, challenge: Challenge, attempt_id: str) -> None:
    state.upsert_attempt(Attempt(
        id=attempt_id, challenge_id=challenge.id, profile="test", role="test",
        backend="mock", workdir=f"/tmp/{attempt_id}",
    ))


def test_tui_candidate_and_verified_flag_are_distinct(tmp_path) -> None:
    state = LocalState(tmp_path / "state.db")
    item = _challenge(state, "rev", "crackme")
    _attempt(state, item, "attempt-rev")
    state.add_flag_candidate(FlagCandidate(
        challenge_id=item.id, challenge_key=item.challenge_key,
        attempt_id="attempt-rev", value="FLAG{candidate}", confidence=.8,
    ))

    candidate = challenge_view(state, item.id)
    assert candidate is not None
    assert candidate.flag_text() == "UNVERIFIED: FLAG{candidate}"
    assert candidate.status != ChallengeStatus.SOLVED.value

    claim = state.claim_attempt(
        state.get_attempt("attempt-rev"), owner="owner", lease_seconds=30,
        max_workers_total=1, max_workers_per_challenge=1,
    )
    assert claim.granted and claim.fencing_token
    candidate_record = state.list_flag_candidates(item.id)[0]
    state.solve_verified(
        candidate_id=candidate_record.id, flag="FLAG{candidate}",
        event=Event(
            team_id="demo-team", member="local", contest="Demo", type="SOLVED",
            challenge_id=item.id, challenge_key=item.challenge_key,
            attempt_id="attempt-rev", payload={"flag": "FLAG{candidate}"},
        ),
        owner="owner", fencing_token=claim.fencing_token,
    )
    verified = challenge_view(state, item.id)
    assert verified is not None
    assert verified.flag_text() == "VERIFIED: FLAG{candidate}"
    assert verified.status == "SOLVED"


def test_candidate_display_priority_and_full_value_are_preserved(tmp_path) -> None:
    state = LocalState(tmp_path / "state.db")
    item = _challenge(state, "crypto", "lattice")
    now = datetime.now(timezone.utc)
    for offset in (1, 2, 3, 4):
        _attempt(state, item, f"attempt-{offset}")
    for value, confidence, status, offset in (
        ("FLAG{new-low}", .2, "CANDIDATE", 3),
        ("FLAG{high-confidence}", .9, "CANDIDATE", 1),
        ("FLAG{being-verified-with-a-very-long-secret-value}", .1, "VERIFYING", 2),
        ("FLAG{rejected}", 1.0, "REJECTED", 4),
    ):
        state.add_flag_candidate(FlagCandidate(
            challenge_id=item.id, challenge_key=item.challenge_key,
            attempt_id=f"attempt-{offset}", value=value, confidence=confidence,
            verification_status=status, created_at=now + timedelta(seconds=offset),
        ))

    view = challenge_view(state, item.id)
    assert view is not None
    assert view.full_flag == "FLAG{being-verified-with-a-very-long-secret-value}"
    assert view.flag_text(compact=True).endswith("…")


def test_local_sqlite_event_projects_to_matching_challenge_key(tmp_path) -> None:
    state = LocalState(tmp_path / "state.db")
    target = _challenge(state, "pwn", "bof")
    other = _challenge(state, "rev", "bof")
    event = Event(
        team_id="demo-team", member="local", contest="Demo", type="SOLVED",
        category="pwn", challenge="bof", challenge_id=target.id,
        challenge_key=target.challenge_key, payload={"flag": "FLAG{local-owned}"},
    )
    projected = LocalEventState.from_events([event])

    owned = challenge_view(state, target.id, event_state=projected)
    untouched = challenge_view(state, other.id, event_state=projected)
    assert owned is not None and owned.flag_text() == "VERIFIED: FLAG{local-owned}"
    assert untouched is not None and untouched.flag_text() == "-"


def test_raw_observation_projects_as_unverified_team_candidate(tmp_path) -> None:
    state = LocalState(tmp_path / "state.db")
    target = _challenge(state, "misc", "remote-observation")
    projected = LocalEventState.from_events([Event(
        team_id="demo-team", member="teammate", contest="Demo", type="FLAG_OBSERVED",
        category="misc", challenge="remote-observation", challenge_id=target.id,
        challenge_key=target.challenge_key, payload={"flag": "FLAG{remote-raw}"},
    )])

    view = challenge_view(state, target.id, event_state=projected)
    assert view is not None
    assert view.flag_text() == "UNVERIFIED: FLAG{remote-raw}"


def test_textual_row_updates_by_challenge_id_not_visual_index_and_copy_is_full(tmp_path) -> None:
    async def exercise() -> None:
        state = LocalState(tmp_path / "state.db")
        first = _challenge(state, "pwn", "bof")
        second = _challenge(state, "web", "sqli")
        app = CTFOSDashboard(_config(tmp_path), state)
        copied: list[str] = []
        app.copy_to_clipboard = copied.append  # type: ignore[method-assign]

        async with app.run_test() as pilot:
            table = app.query_one("#challenges", DataTable)
            # Visual order differs from creation order; stable keys still own updates.
            table.sort("problem", reverse=True)
            long_flag = "FLAG{" + "x" * 80 + "}"
            _attempt(state, first, "attempt-bof")
            state.add_flag_candidate(FlagCandidate(
                challenge_id=first.id, challenge_key=first.challenge_key,
                attempt_id="attempt-bof", value=long_flag,
            ))
            event = Event(
                team_id="demo-team", member="local", contest="Demo",
                type="FLAG_CANDIDATE", category="pwn", challenge="bof",
                challenge_id=first.id, challenge_key=first.challenge_key,
                attempt_id="attempt-bof", payload={"flag": long_flag},
            )
            app.notify_challenge_changed(first.id, event)
            await pilot.pause()

            assert str(table.get_cell(first.id, "flag")).startswith("UNVERIFIED: FLAG{")
            assert table.get_cell(second.id, "flag") == "-"
            assert table.get_cell(first.id, "flag") == f"UNVERIFIED: {long_flag}"

            row_index = table.get_row_index(first.id)
            table.move_cursor(row=row_index)
            await pilot.pause()
            detail = str(app.query_one("#challenge-detail", Static).renderable)
            log = str(app.query_one("#event-log", Static).renderable)
            assert long_flag in detail
            assert "[LOCAL][pwn/bof][attempt-bof] FLAG_CANDIDATE" in log
            app.action_copy_flag()
            assert copied == [long_flag]

    asyncio.run(exercise())


def test_background_safe_notification_updates_matching_row(tmp_path) -> None:
    async def exercise() -> None:
        state = LocalState(tmp_path / "state.db")
        item = _challenge(state, "web", "race")
        app = CTFOSDashboard(_config(tmp_path), state)
        async with app.run_test() as pilot:
            _attempt(state, item, "thread-attempt")
            state.add_flag_candidate(FlagCandidate(
                challenge_id=item.id, challenge_key=item.challenge_key,
                attempt_id="thread-attempt", value="FLAG{thread-safe}",
            ))
            notifier = Thread(target=app.notify_challenge_changed, args=(item.id,))
            notifier.start()
            await pilot.pause()
            notifier.join(timeout=2)
            assert not notifier.is_alive()
            table = app.query_one("#challenges", DataTable)
            assert table.get_cell(item.id, "flag") == "UNVERIFIED: FLAG{thread-safe}"

    asyncio.run(exercise())


def test_committed_flag_event_immediately_updates_only_matching_row_and_unsubscribes(tmp_path) -> None:
    async def exercise() -> None:
        state = LocalState(tmp_path / "state.db")
        target = _challenge(state, "pwn", "instant")
        other = _challenge(state, "web", "untouched")
        _attempt(state, target, "instant-attempt")
        config = _config(tmp_path)
        config.raw["watcher"]["poll_interval_sec"] = 3600
        app = CTFOSDashboard(config, state)
        refreshed: list[str] = []

        async with app.run_test():
            original = app.refresh_challenge

            def tracking_refresh(challenge_id: str, event=None) -> None:
                refreshed.append(challenge_id)
                original(challenge_id, event)

            app.refresh_challenge = tracking_refresh  # type: ignore[method-assign]
            state.add_flag_candidate(FlagCandidate(
                challenge_id=target.id, challenge_key=target.challenge_key,
                attempt_id="instant-attempt", value="FLAG{instant}",
            ))
            state.append_event(Event(
                team_id="demo-team", member="local", contest="Demo",
                type="FLAG_CANDIDATE", category="pwn", challenge="instant",
                challenge_id=target.id, challenge_key=target.challenge_key,
                attempt_id="instant-attempt", payload={"flag": "FLAG{instant}"},
            ))

            table = app.query_one("#challenges", DataTable)
            assert refreshed == [target.id]
            assert table.get_cell(target.id, "flag") == "UNVERIFIED: FLAG{instant}"
            assert table.get_cell(other.id, "flag") == "-"

        refreshed.clear()
        state.append_event(Event(
            team_id="demo-team", member="local", contest="Demo", type="VERIFYING",
            category="pwn", challenge="instant", challenge_id=target.id,
            challenge_key=target.challenge_key, payload={"flag": "FLAG{instant}"},
        ))
        assert refreshed == []

    asyncio.run(exercise())


def test_raw_observation_immediately_reaches_tui_without_waiting_for_poll(tmp_path) -> None:
    async def exercise() -> None:
        state = LocalState(tmp_path / "state.db")
        target = _challenge(state, "web", "raw-stream")
        _attempt(state, target, "raw-attempt")
        config = _config(tmp_path)
        config.raw["watcher"]["poll_interval_sec"] = 3600
        app = CTFOSDashboard(config, state)

        async with app.run_test():
            candidate = FlagCandidate(
                challenge_id=target.id, challenge_key=target.challenge_key,
                attempt_id="raw-attempt", value="FLAG{seen-before-verification}",
                verification_status="RAW_CANDIDATE",
            )
            claim = state.claim_attempt(
                state.get_attempt("raw-attempt"), owner="owner", lease_seconds=30,
                max_workers_total=1, max_workers_per_challenge=1,
            )
            assert claim.granted and claim.fencing_token
            state.record_candidate(
                candidate,
                Event(
                    team_id="demo-team", member="local", contest="Demo",
                    type="FLAG_OBSERVED", category="web", challenge="raw-stream",
                    challenge_id=target.id, challenge_key=target.challenge_key,
                    attempt_id="raw-attempt", payload={"flag": candidate.value},
                ),
                owner="owner", fencing_token=claim.fencing_token,
                promote_challenge_status=False,
            )

            table = app.query_one("#challenges", DataTable)
            assert str(table.get_cell(target.id, "flag")).startswith("UNVERIFIED: FLAG{seen-before-verifi")
            log = str(app.query_one("#event-log", Static).renderable)
            assert "FLAG_OBSERVED: FLAG{seen-before-verification}" in log

    asyncio.run(exercise())
