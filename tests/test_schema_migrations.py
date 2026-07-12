from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from ctf_os.local_state import CURRENT_SCHEMA_VERSION, LocalState, StateError, StateTransitionError
from ctf_os.models import Attempt, Challenge, ChallengeSession, ContractTask, Event, FlagCandidate


LEGACY_V1_SCHEMA = """
CREATE TABLE challenges (
  id TEXT PRIMARY KEY, contest TEXT NOT NULL, category TEXT NOT NULL,
  name TEXT NOT NULL, slug TEXT NOT NULL, score INTEGER, remote TEXT,
  description TEXT, hint TEXT, flag_format TEXT, flag_pattern TEXT,
  status TEXT NOT NULL, assignee TEXT, flag TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE(contest, category, name)
);
CREATE TABLE attempts (
  id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL, profile TEXT NOT NULL,
  role TEXT NOT NULL, backend TEXT NOT NULL, model TEXT, pid INTEGER,
  container_name TEXT, workdir TEXT NOT NULL, status TEXT NOT NULL,
  started_at TEXT, ended_at TEXT, token_total INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(challenge_id) REFERENCES challenges(id)
);
CREATE TABLE events (
  id TEXT PRIMARY KEY, challenge_id TEXT, attempt_id TEXT, type TEXT NOT NULL,
  message TEXT, payload_json TEXT, created_at TEXT NOT NULL,
  FOREIGN KEY(challenge_id) REFERENCES challenges(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);
CREATE TABLE flag_candidates (
  id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL, attempt_id TEXT,
  value TEXT NOT NULL, source TEXT, confidence REAL, verified INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  FOREIGN KEY(challenge_id) REFERENCES challenges(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);
CREATE TABLE coordinator_leases (
  contest TEXT PRIMARY KEY, owner TEXT NOT NULL, heartbeat_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE attempt_leases (
  challenge_id TEXT NOT NULL, profile TEXT NOT NULL, attempt_id TEXT NOT NULL UNIQUE,
  owner TEXT NOT NULL, heartbeat_at TEXT NOT NULL, expires_at TEXT NOT NULL,
  PRIMARY KEY(challenge_id, profile),
  FOREIGN KEY(challenge_id) REFERENCES challenges(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);
CREATE TABLE outbox (
  event_id TEXT PRIMARY KEY, event_json TEXT NOT NULL, created_at TEXT NOT NULL,
  published_at TEXT, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT,
  FOREIGN KEY(event_id) REFERENCES events(id)
);
"""


def _create_legacy_v1(path, *, user_version: int = 1) -> dict[str, str]:
    created_at = "2026-07-10T00:00:00.000000+00:00"
    event = Event(
        id="event-legacy", timestamp=created_at, team_id="team", member="member",
        contest="contest", type="FINDING", challenge_id="challenge-legacy",
        attempt_id="attempt-legacy", message="legacy event", payload={"source": "v1"},
    )
    event_json = json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":"))
    with sqlite3.connect(path) as conn:
        conn.executescript(LEGACY_V1_SCHEMA)
        conn.execute(
            "INSERT INTO challenges VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("challenge-legacy", "contest", "web", "legacy", "web-legacy", 100, None,
             "legacy description", None, None, None, "QUEUED", None, None, created_at, created_at),
        )
        conn.execute(
            "INSERT INTO attempts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("attempt-legacy", "challenge-legacy", "default", "recon", "mock", None,
             None, None, "/work", "QUEUED", created_at, None, 7),
        )
        conn.execute(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("event-legacy", "challenge-legacy", "attempt-legacy", "FINDING", "legacy event",
             '{"source":"v1"}', created_at),
        )
        conn.execute(
            "INSERT INTO outbox VALUES (?, ?, ?, ?, ?, ?)",
            ("event-legacy", event_json, created_at, None, 2, "temporary failure"),
        )
        conn.execute(f"PRAGMA user_version = {user_version}")
    return {"created_at": created_at, "event_json": event_json}


def _schema_version(path) -> int:
    with sqlite3.connect(path) as conn:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])


def _table_columns(path, table: str) -> set[str]:
    with sqlite3.connect(path) as conn:
        return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


def test_fresh_database_uses_ordered_migrations_and_is_idempotent(tmp_path):
    path = tmp_path / "state.db"

    LocalState(path)

    assert _schema_version(path) == CURRENT_SCHEMA_VERSION
    assert {"synthetic"} <= _table_columns(path, "challenges")
    assert {"event_json"} <= _table_columns(path, "events")
    assert {"fencing_token"} <= _table_columns(path, "attempt_leases")
    with sqlite3.connect(path) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        indexes = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert {"attempt_fence_tokens", "model_cooldowns"} <= tables
        assert {"idx_attempts_challenge", "idx_events_challenge", "idx_flags_challenge", "idx_attempt_leases_expiry", "idx_outbox_pending"} <= indexes
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"

    LocalState(path)
    assert _schema_version(path) == CURRENT_SCHEMA_VERSION


def test_legacy_v1_migration_preserves_challenge_attempt_event_and_outbox_data(tmp_path):
    path = tmp_path / "legacy-v1.db"
    legacy = _create_legacy_v1(path)

    state = LocalState(path)

    assert _schema_version(path) == CURRENT_SCHEMA_VERSION
    challenge = state.get_challenge("challenge-legacy")
    attempt = state.get_attempt("attempt-legacy")
    assert challenge is not None and (challenge.name, challenge.synthetic) == ("legacy", False)
    assert attempt is not None and (attempt.token_total, attempt.cleanup_status, attempt.fencing_token) == (7, None, None)
    assert state.list_events(challenge_id="challenge-legacy")[0].payload == {"source": "v1"}
    outbox = state.pending_outbox()
    assert len(outbox) == 1
    assert (outbox[0].event.id, outbox[0].attempts, outbox[0].last_error) == (
        "event-legacy", 2, "temporary failure",
    )
    assert {"synthetic"} <= _table_columns(path, "challenges")
    assert {"synthetic", "cleanup_status", "cleanup_message", "lease_owner", "fencing_token"} <= _table_columns(path, "attempts")
    assert {"event_json"} <= _table_columns(path, "events")
    assert {"verification_status", "verification_reason", "synthetic"} <= _table_columns(path, "flag_candidates")

    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT event_json FROM outbox WHERE event_id='event-legacy'").fetchone()[0] == legacy["event_json"]


def test_unversioned_current_database_with_data_is_upgraded_without_loss(tmp_path):
    path = tmp_path / "unversioned-current.db"
    state = LocalState(path)
    challenge = state.upsert_challenge(Challenge(contest="contest", category="web", name="kept"))
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA user_version = 0")

    reopened = LocalState(path)

    assert _schema_version(path) == CURRENT_SCHEMA_VERSION
    assert reopened.get_challenge(challenge.id) is not None


def test_future_schema_version_refuses_startup_without_downgrade(tmp_path):
    path = tmp_path / "future.db"
    _create_legacy_v1(path, user_version=CURRENT_SCHEMA_VERSION + 1)

    with pytest.raises(StateError, match="upgrade CTF-OS.*refusing to downgrade"):
        LocalState(path)

    assert _schema_version(path) == CURRENT_SCHEMA_VERSION + 1


def test_migration_failure_rolls_back_schema_data_and_user_version(tmp_path, monkeypatch):
    path = tmp_path / "migration-failure.db"
    _create_legacy_v1(path)

    def fail_after_writes(self, conn):
        conn.execute("UPDATE challenges SET name='corrupted'")
        conn.execute("ALTER TABLE events ADD COLUMN migration_failure_probe TEXT")
        raise RuntimeError("injected migration failure")

    monkeypatch.setattr(LocalState, "_migrate_v1_to_v2", fail_after_writes)

    with pytest.raises(RuntimeError, match="injected migration failure"):
        LocalState(path)

    assert _schema_version(path) == 1
    assert "synthetic" not in _table_columns(path, "challenges")
    assert "migration_failure_probe" not in _table_columns(path, "events")
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT name FROM challenges WHERE id='challenge-legacy'").fetchone()[0] == "legacy"


def test_v2_to_v3_preserves_model_global_cooldown_and_adds_selection_identity(tmp_path):
    path = tmp_path / "legacy-v2.db"
    _create_legacy_v1(path, user_version=0)
    with sqlite3.connect(path) as conn:
        # Recreate exactly the v2 additive state, then let normal startup
        # exercise only the ordered v2 -> v3 transition.
        conn.execute("ALTER TABLE attempts ADD COLUMN synthetic INTEGER NOT NULL DEFAULT 0")
        conn.execute("ALTER TABLE attempts ADD COLUMN cleanup_status TEXT")
        conn.execute("ALTER TABLE attempts ADD COLUMN cleanup_message TEXT")
        conn.execute("ALTER TABLE attempts ADD COLUMN lease_owner TEXT")
        conn.execute("ALTER TABLE attempts ADD COLUMN fencing_token INTEGER")
        conn.execute("ALTER TABLE events ADD COLUMN event_json TEXT")
        conn.execute("ALTER TABLE flag_candidates ADD COLUMN verification_status TEXT NOT NULL DEFAULT 'CANDIDATE'")
        conn.execute("ALTER TABLE flag_candidates ADD COLUMN verification_reason TEXT")
        conn.execute("ALTER TABLE flag_candidates ADD COLUMN synthetic INTEGER NOT NULL DEFAULT 0")
        conn.execute("ALTER TABLE attempt_leases ADD COLUMN fencing_token INTEGER NOT NULL DEFAULT 0")
        conn.execute("CREATE TABLE attempt_fence_tokens (token INTEGER PRIMARY KEY AUTOINCREMENT)")
        conn.execute("CREATE TABLE model_cooldowns (model TEXT PRIMARY KEY, reason TEXT NOT NULL, expires_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
        conn.execute(
            "INSERT INTO model_cooldowns VALUES (?, ?, ?, ?)",
                ("gpt-5.6-terra", "rate limited", "2099-07-11T00:00:00.000000+00:00", "2026-07-10T00:00:00.000000+00:00"),
        )
        conn.execute("PRAGMA user_version = 2")

    state = LocalState(path)

    assert _schema_version(path) == CURRENT_SCHEMA_VERSION
    assert {"model_profile", "reasoning_effort", "session_id", "resume_id"} <= _table_columns(path, "attempts")
    assert state.model_in_cooldown("gpt-5.6-terra")
    # A pre-v3 raw-model cooldown remains an explicit model-global override.
    assert state.model_in_cooldown("gpt-5.6-terra", selection_key="selection:terra_high:gpt-5.6-terra:high")
    with sqlite3.connect(path) as conn:
        row = conn.execute("SELECT selection_key, model FROM model_cooldowns").fetchone()
    assert row == ("model:gpt-5.6-terra", "gpt-5.6-terra")


def _create_legacy_v3(path) -> None:
    _create_legacy_v1(path, user_version=0)
    with sqlite3.connect(path) as conn:
        conn.execute("ALTER TABLE challenges ADD COLUMN synthetic INTEGER NOT NULL DEFAULT 0")
        conn.execute("ALTER TABLE attempts ADD COLUMN synthetic INTEGER NOT NULL DEFAULT 0")
        conn.execute("ALTER TABLE attempts ADD COLUMN cleanup_status TEXT")
        conn.execute("ALTER TABLE attempts ADD COLUMN cleanup_message TEXT")
        conn.execute("ALTER TABLE attempts ADD COLUMN lease_owner TEXT")
        conn.execute("ALTER TABLE attempts ADD COLUMN fencing_token INTEGER")
        conn.execute("ALTER TABLE attempts ADD COLUMN model_profile TEXT")
        conn.execute("ALTER TABLE attempts ADD COLUMN reasoning_effort TEXT")
        conn.execute("ALTER TABLE events ADD COLUMN event_json TEXT")
        conn.execute("ALTER TABLE flag_candidates ADD COLUMN verification_status TEXT NOT NULL DEFAULT 'CANDIDATE'")
        conn.execute("ALTER TABLE flag_candidates ADD COLUMN verification_reason TEXT")
        conn.execute("ALTER TABLE flag_candidates ADD COLUMN synthetic INTEGER NOT NULL DEFAULT 0")
        conn.execute("ALTER TABLE attempt_leases ADD COLUMN fencing_token INTEGER NOT NULL DEFAULT 0")
        conn.execute("CREATE TABLE attempt_fence_tokens (token INTEGER PRIMARY KEY AUTOINCREMENT)")
        conn.execute(
            "CREATE TABLE model_cooldowns (selection_key TEXT PRIMARY KEY, model TEXT NOT NULL, reason TEXT NOT NULL, expires_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
        )
        conn.execute(
            "UPDATE attempts SET model_profile=?, reasoning_effort=?, cleanup_status=?, lease_owner=?, fencing_token=? WHERE id=?",
            ("legacy-profile", "medium", "CLEANED", "legacy-owner", 17, "attempt-legacy"),
        )
        conn.execute("PRAGMA user_version = 3")


def test_v3_to_v4_adds_nullable_codex_session_columns_without_losing_attempt_data(tmp_path):
    path = tmp_path / "legacy-v3.db"
    _create_legacy_v3(path)

    state = LocalState(path)

    assert CURRENT_SCHEMA_VERSION == 10
    assert _schema_version(path) == 10
    assert {"session_id", "resume_id"} <= _table_columns(path, "attempts")
    attempt = state.get_attempt("attempt-legacy")
    assert attempt is not None
    assert (
        attempt.model_profile,
        attempt.reasoning_effort,
        attempt.cleanup_status,
        attempt.lease_owner,
        attempt.fencing_token,
        attempt.session_id,
        attempt.resume_id,
    ) == ("legacy-profile", "medium", "CLEANED", "legacy-owner", 17, None, None)


def test_v3_to_v4_failure_rolls_back_columns_data_and_schema_version(tmp_path, monkeypatch):
    path = tmp_path / "v3-failure.db"
    _create_legacy_v3(path)

    def fail_after_writes(self, conn):
        conn.execute("ALTER TABLE attempts ADD COLUMN session_id TEXT")
        conn.execute("UPDATE attempts SET model_profile='corrupted'")
        raise RuntimeError("injected v4 migration failure")

    monkeypatch.setattr(LocalState, "_migrate_v3_to_v4", fail_after_writes, raising=False)

    with pytest.raises(RuntimeError, match="injected v4 migration failure"):
        LocalState(path)

    assert _schema_version(path) == 3
    assert "session_id" not in _table_columns(path, "attempts")
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT model_profile FROM attempts WHERE id='attempt-legacy'").fetchone()[0] == "legacy-profile"


def test_authoritative_team_normalizes_legacy_challenge_ownership_on_open(tmp_path):
    path = tmp_path / "legacy-keys.db"
    state = LocalState(path)
    challenge = state.upsert_challenge(
        Challenge(contest="SCA CTF 2026", category="pwn", name="bof")
    )
    state.add_flag_candidate(FlagCandidate(
        id="candidate-legacy", challenge_id=challenge.id,
        challenge_key=challenge.challenge_key, value="SCA{owned}", source="worker",
    ))
    state.append_event(Event(
        id="event-owned", team_id="sca-team", member="jiwoong",
        contest=challenge.contest, category=challenge.category,
        challenge=challenge.name, challenge_id=challenge.id,
        challenge_key=challenge.challenge_key, type="FLAG_CANDIDATE",
        payload={"flag": "SCA{owned}"},
    ))

    rebound = LocalState(path, team_id="sca-team")
    expected = "sca-team:sca-ctf-2026:pwn:bof"
    assert rebound.get_challenge(challenge.id).challenge_key == expected
    assert rebound.list_flag_candidates(challenge.id)[0].challenge_key == expected
    assert rebound.list_events(challenge_id=challenge.id)[0].challenge_key == expected
    with sqlite3.connect(path) as conn:
        assert conn.execute(
            "SELECT value FROM state_metadata WHERE key='team_id'"
        ).fetchone()[0] == "sca-team"
        outbox = json.loads(conn.execute(
            "SELECT event_json FROM outbox WHERE event_id='event-owned'"
        ).fetchone()[0])
        assert outbox["challenge_key"] == expected

    # The persisted binding makes later opens deterministic without requiring
    # the caller to supply config again.
    assert LocalState(path).get_challenge(challenge.id).challenge_key == expected


def test_team_binding_is_idempotent_and_refuses_cross_team_rewrite(tmp_path):
    path = tmp_path / "bound.db"
    first = LocalState(path, team_id="team-a")
    challenge = first.upsert_challenge(Challenge(
        contest="Demo", category="web", name="login",
        challenge_key="team-a:demo:web:login",
    ))

    assert LocalState(path, team_id="team-a").get_challenge(challenge.id).challenge_key == (
        "team-a:demo:web:login"
    )
    with pytest.raises(StateError, match="bound to team 'team-a'"):
        LocalState(path, team_id="team-b")

    # The rejected open rolls back and preserves the original ownership.
    assert LocalState(path).get_challenge(challenge.id).challenge_key == (
        "team-a:demo:web:login"
    )


def test_local_state_binds_complete_node_identity_and_refuses_reuse(tmp_path):
    path = tmp_path / "node.db"
    LocalState(
        path,
        team_id="four-person-team",
        member_name="alice",
        contest_name="Main CTF",
    )

    with sqlite3.connect(path) as conn:
        assert dict(conn.execute("SELECT key, value FROM state_metadata")) == {
            "team_id": "four-person-team",
            "member_name": "alice",
            "contest_name": "Main CTF",
        }

    LocalState(
        path,
        team_id="four-person-team",
        member_name="alice",
        contest_name="Main CTF",
    )
    for changed, message in (
        ({"team_id": "split-team-a"}, "another team's data"),
        ({"member_name": "bob"}, "config member.name is 'bob'"),
        ({"contest_name": "Next CTF"}, "config contest.name is 'Next CTF'"),
    ):
        identity = {
            "team_id": "four-person-team",
            "member_name": "alice",
            "contest_name": "Main CTF",
            **changed,
        }
        with pytest.raises(StateError, match=message):
            LocalState(path, **identity)

    # Failed opens are atomic: they cannot relabel the original local node.
    with sqlite3.connect(path) as conn:
        assert dict(conn.execute("SELECT key, value FROM state_metadata")) == {
            "team_id": "four-person-team",
            "member_name": "alice",
            "contest_name": "Main CTF",
        }


def test_v6_member_and_contest_evidence_prevents_wrong_first_v7_binding(tmp_path):
    path = tmp_path / "legacy-v6.db"
    legacy = LocalState(path, team_id="team")
    challenge = legacy.upsert_challenge(
        Challenge(contest="Legacy CTF", category="web", name="login")
    )
    legacy.append_event(Event(
        team_id="team", member="alice", contest="Legacy CTF", type="FINDING",
        challenge_id=challenge.id,
    ))
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA user_version = 6")

    with pytest.raises(StateError, match="legacy event data.*member.name 'alice'.*member.name is 'bob'"):
        LocalState(
            path, team_id="team", member_name="bob", contest_name="Legacy CTF"
        )
    assert _schema_version(path) == 6

    with pytest.raises(StateError, match="legacy challenge data.*contest.name 'Legacy CTF'.*contest.name is 'Other CTF'"):
        LocalState(
            path, team_id="team", member_name="alice", contest_name="Other CTF"
        )
    assert _schema_version(path) == 6

    LocalState(
        path, team_id="team", member_name="alice", contest_name="Legacy CTF"
    )
    assert _schema_version(path) == CURRENT_SCHEMA_VERSION


def test_attempt_session_ids_require_the_active_lease_and_reject_stale_writes(tmp_path):
    now = datetime(2026, 7, 10, tzinfo=timezone.utc)
    state = LocalState(tmp_path / "state.db", clock=lambda: now)
    challenge = state.upsert_challenge(Challenge(contest="Demo", category="web", name="login"))
    attempt = Attempt(id="session-attempt", challenge_id=challenge.id, profile="recon", role="recon", backend="codex", workdir="/work")
    claim = state.claim_attempt(attempt, owner="owner", lease_seconds=1, max_workers_total=1, max_workers_per_challenge=1)
    assert claim.granted and claim.fencing_token

    stored = state.record_attempt_session_ids(
        attempt.id, session_id="session-live", resume_id="resume-live",
        owner="owner", fencing_token=claim.fencing_token,
    )
    assert (stored.session_id, stored.resume_id) == ("session-live", "resume-live")

    with pytest.raises(StateTransitionError, match="lease"):
        state.record_attempt_session_ids(
            attempt.id, session_id="session-stale", resume_id="resume-stale",
            owner="owner", fencing_token=claim.fencing_token, now=now + timedelta(seconds=2),
        )
    persisted = state.get_attempt(attempt.id)
    assert persisted and (persisted.session_id, persisted.resume_id) == ("session-live", "resume-live")


def test_fenced_cooldown_refuses_a_stale_lease_without_event_or_state_write(tmp_path):
    now = datetime(2026, 7, 10, tzinfo=timezone.utc)
    state = LocalState(tmp_path / "state.db", clock=lambda: now)
    challenge = state.upsert_challenge(Challenge(contest="Demo", category="web", name="login"))
    attempt = Attempt(id="stale", challenge_id=challenge.id, profile="recon_fast", role="recon", backend="codex", workdir="/work")
    claim = state.claim_attempt(attempt, owner="old", lease_seconds=1, max_workers_total=1, max_workers_per_challenge=1)
    assert claim.granted and claim.fencing_token

    event = Event(team_id="team", member="member", contest="Demo", type="MODEL_COOLDOWN", challenge_id=challenge.id, attempt_id=attempt.id)
    with pytest.raises(StateTransitionError, match="lease"):
        state.record_model_cooldown(
            model="gpt-5.6-terra", selection_key="selection:terra:gpt-5.6-terra:high",
            reason="rate limited", seconds=30, event=event, owner="old", fencing_token=claim.fencing_token,
            now=now + timedelta(seconds=2),
        )
    assert not state.model_in_cooldown("gpt-5.6-terra", selection_key="selection:terra:gpt-5.6-terra:high")
    assert not state.list_events(challenge_id=challenge.id)


def test_v8_to_v9_preserves_tasks_and_backfills_execution_spec(tmp_path):
    path = tmp_path / "legacy-v8.db"
    state = LocalState(path)
    challenge = state.upsert_challenge(Challenge(contest="Demo", category="pwn", name="legacy-task"))
    session = state.upsert_challenge_session(ChallengeSession(
        challenge_id=challenge.id, leader_model="gpt-5.6-sol"
    ))
    task = state.upsert_contract_task(ContractTask(
        id="legacy-contract", session_id=session.id, challenge_id=challenge.id,
        branch="g1:A", role="sol_xhigh", objective="take over exploit",
    ))
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("ALTER TABLE contract_tasks RENAME TO contract_tasks_v9")
        conn.execute("""
            CREATE TABLE contract_tasks (
              id TEXT PRIMARY KEY, session_id TEXT NOT NULL, challenge_id TEXT NOT NULL,
              branch TEXT NOT NULL, role TEXT NOT NULL, objective TEXT NOT NULL,
              status TEXT NOT NULL, success_criteria_json TEXT NOT NULL,
              deliverables_json TEXT NOT NULL, failure_handoff TEXT,
              depends_on_json TEXT NOT NULL, assigned_attempt_id TEXT,
              result_summary TEXT, evidence_ids_json TEXT NOT NULL,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            INSERT INTO contract_tasks (
              id,session_id,challenge_id,branch,role,objective,status,
              success_criteria_json,deliverables_json,failure_handoff,depends_on_json,
              assigned_attempt_id,result_summary,evidence_ids_json,created_at,updated_at
            ) SELECT id,session_id,challenge_id,branch,role,objective,status,
              success_criteria_json,deliverables_json,failure_handoff,depends_on_json,
              assigned_attempt_id,result_summary,evidence_ids_json,created_at,updated_at
              FROM contract_tasks_v9
        """)
        conn.execute("DROP TABLE contract_tasks_v9")
        conn.execute("PRAGMA user_version=8")

    migrated = LocalState(path).get_contract_task(task.id)
    assert migrated is not None
    assert migrated.model_profile == "sol_xhigh"
    assert migrated.reasoning_effort == "max"
    assert migrated.prompt_family == "takeover"
    assert (migrated.backend, migrated.timeout_sec, migrated.tool_strategy, migrated.priority) == (
        "codex", 1200, "exploit_build", 50
    )
