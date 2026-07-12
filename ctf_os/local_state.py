"""Durable local state, leases, and transactional local event outbox.

The database is deliberately scoped to one local contest output directory.  It
is a concurrency authority for *this node only*: no table or method here can
claim work on another member's machine.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime
import json
from pathlib import Path
import sqlite3
from threading import RLock
from typing import TYPE_CHECKING, Any, Callable, Iterable, Iterator, TypeVar

if TYPE_CHECKING:
    from .config import AppConfig

from .models import (
    Attempt,
    AttemptStatus,
    Challenge,
    ChallengeSession,
    ChallengeStatus,
    ContractTask,
    ContractTaskStatus,
    Event,
    FlagCandidate,
    SessionStatus,
    ensure_utc,
    timestamp_text,
    utc_now,
)


class StateTransitionError(ValueError):
    pass


class StateError(ValueError):
    """Raised when a local-state database cannot be opened safely."""


CURRENT_SCHEMA_VERSION = 10


@dataclass(frozen=True)
class LeaseClaim:
    granted: bool
    reason: str = ""
    fencing_token: int | None = None


@dataclass(frozen=True)
class RecoveryResult:
    stale_attempt_ids: tuple[str, ...]
    requeued_challenge_ids: tuple[str, ...]


@dataclass(frozen=True)
class OutboxRecord:
    event: Event
    attempts: int
    last_error: str | None


_OperationResult = TypeVar("_OperationResult")


_TRANSITIONS: dict[ChallengeStatus, frozenset[ChallengeStatus]] = {
    ChallengeStatus.DISCOVERED: frozenset({ChallengeStatus.QUEUED, ChallengeStatus.PAUSED}),
    ChallengeStatus.QUEUED: frozenset({ChallengeStatus.RUNNING, ChallengeStatus.PAUSED, ChallengeStatus.FAILED}),
    ChallengeStatus.RUNNING: frozenset({ChallengeStatus.STUCK, ChallengeStatus.FLAG_CANDIDATE, ChallengeStatus.PAUSED, ChallengeStatus.FAILED}),
    ChallengeStatus.STUCK: frozenset({ChallengeStatus.HINTING, ChallengeStatus.RUNNING, ChallengeStatus.PAUSED, ChallengeStatus.FAILED}),
    ChallengeStatus.HINTING: frozenset({ChallengeStatus.RUNNING, ChallengeStatus.STUCK, ChallengeStatus.PAUSED, ChallengeStatus.FAILED}),
    ChallengeStatus.FLAG_CANDIDATE: frozenset({ChallengeStatus.VERIFYING, ChallengeStatus.RUNNING, ChallengeStatus.PAUSED, ChallengeStatus.FAILED}),
    ChallengeStatus.VERIFYING: frozenset({ChallengeStatus.SOLVED, ChallengeStatus.FLAG_CANDIDATE, ChallengeStatus.RUNNING, ChallengeStatus.PAUSED, ChallengeStatus.FAILED}),
    # SOLVED is intentionally terminal.  The v1.3 requirements do not
    # authorize an administrative reset endpoint, so none is exposed here.
    ChallengeStatus.SOLVED: frozenset(),
    ChallengeStatus.FAILED: frozenset({ChallengeStatus.QUEUED, ChallengeStatus.PAUSED}),
    ChallengeStatus.PAUSED: frozenset({ChallengeStatus.QUEUED, ChallengeStatus.RUNNING, ChallengeStatus.FAILED}),
}


class LocalState:
    """SQLite repository with process-safe coordinator/attempt leases.

    ``clock`` is injected to make expiry and recovery deterministic in tests.
    It must return an aware datetime (the same contract as :func:`utc_now`).
    """

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], datetime] = utc_now,
        team_id: str | None = None,
        member_name: str | None = None,
        contest_name: str | None = None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._team_id = team_id.strip() if team_id is not None else None
        self._member_name = member_name.strip() if member_name is not None else None
        self._contest_name = contest_name.strip() if contest_name is not None else None
        self._bound_team_id: str | None = None
        self._event_listeners: list[Callable[[Event], None]] = []
        self._event_listener_lock = RLock()
        if team_id is not None and not self._team_id:
            raise ValueError("team_id must be non-empty when provided")
        if member_name is not None and not self._member_name:
            raise ValueError("member_name must be non-empty when provided")
        if contest_name is not None and not self._contest_name:
            raise ValueError("contest_name must be non-empty when provided")
        self.initialize()

    @classmethod
    def for_config(
        cls,
        config: "AppConfig",
        *,
        contest_name: str | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> "LocalState":
        """Open the configured DB while enforcing its complete node identity."""
        resolved_contest = contest_name or config.contest_name
        return cls(
            config.state_path(resolved_contest),
            clock=clock,
            team_id=config.team_id,
            member_name=config.member_name,
            contest_name=resolved_contest,
        )

    def subscribe_events(self, listener: Callable[[Event], None]) -> Callable[[], None]:
        """Subscribe to committed events produced through this repository.

        Delivery is an in-process acceleration for reactive views. SQLite and
        the append-only outbox remain authoritative, so consumers must retain
        their polling/restart fallback.
        """
        with self._event_listener_lock:
            self._event_listeners.append(listener)

        def unsubscribe() -> None:
            with self._event_listener_lock:
                try:
                    self._event_listeners.remove(listener)
                except ValueError:
                    pass

        return unsubscribe

    def _notify_committed_events(self, events: Iterable[Event]) -> None:
        with self._event_listener_lock:
            listeners = tuple(self._event_listeners)
        for event in events:
            for listener in listeners:
                try:
                    listener(event)
                except Exception:
                    # A dashboard is observational and may never roll back or
                    # fail an already-committed coordinator operation.
                    continue

    def _now(self, value: datetime | str | None = None) -> str:
        return timestamp_text(value if value is not None else self._clock())

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        """Open the database with the schema required by this release.

        ``user_version`` is deliberately updated only after each migration has
        succeeded, and the complete upgrade runs in one SQLite transaction.
        This also makes a pre-versioning database (``user_version = 0``)
        follow the same ordered path as a fresh database.
        """
        conn = self._connect()
        try:
            # journal_mode cannot be changed inside a transaction.  The
            # schema/data migration below is still one atomic transaction.
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("BEGIN IMMEDIATE")
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if version < 0:
                raise StateError(f"invalid local-state schema version {version}")
            if version > CURRENT_SCHEMA_VERSION:
                raise StateError(
                    f"local-state schema version {version} is newer than this CTF-OS "
                    f"release supports ({CURRENT_SCHEMA_VERSION}); upgrade CTF-OS before "
                    "opening this database (refusing to downgrade)."
                )
            while version < CURRENT_SCHEMA_VERSION:
                self._apply_migration(conn, version)
                version += 1
                conn.execute(f"PRAGMA user_version = {version}")
            self._bind_team_identity(conn)
            conn.commit()
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def _apply_migration(self, conn: sqlite3.Connection, version: int) -> None:
        if version == 0:
            self._migrate_v0_to_v1(conn)
        elif version == 1:
            self._migrate_v1_to_v2(conn)
        elif version == 2:
            self._migrate_v2_to_v3(conn)
        elif version == 3:
            self._migrate_v3_to_v4(conn)
        elif version == 4:
            self._migrate_v4_to_v5(conn)
        elif version == 5:
            self._migrate_v5_to_v6(conn)
        elif version == 6:
            self._migrate_v6_to_v7(conn)
        elif version == 7:
            self._migrate_v7_to_v8(conn)
        elif version == 8:
            self._migrate_v8_to_v9(conn)
        elif version == 9:
            self._migrate_v9_to_v10(conn)
        else:  # Defensive guard for future edits to CURRENT_SCHEMA_VERSION.
            raise StateError(f"no migration is registered from schema version {version}")

    @staticmethod
    def _migrate_v0_to_v1(conn: sqlite3.Connection) -> None:
        """Create the original schema, or recognize an unversioned legacy DB."""
        statements = (
            """
                CREATE TABLE IF NOT EXISTS challenges (
                  id TEXT PRIMARY KEY, contest TEXT NOT NULL, category TEXT NOT NULL,
                  name TEXT NOT NULL, slug TEXT NOT NULL, score INTEGER, remote TEXT,
                  description TEXT, hint TEXT, flag_format TEXT, flag_pattern TEXT,
                  status TEXT NOT NULL, assignee TEXT, flag TEXT,
                  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                  UNIQUE(contest, category, name)
                )
            """,
            """
                CREATE TABLE IF NOT EXISTS attempts (
                  id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL, profile TEXT NOT NULL,
                  role TEXT NOT NULL, backend TEXT NOT NULL, model TEXT, pid INTEGER,
                  container_name TEXT, workdir TEXT NOT NULL, status TEXT NOT NULL,
                  started_at TEXT, ended_at TEXT, token_total INTEGER NOT NULL DEFAULT 0,
                  FOREIGN KEY(challenge_id) REFERENCES challenges(id)
                )
            """,
            """
                CREATE TABLE IF NOT EXISTS events (
                  id TEXT PRIMARY KEY, challenge_id TEXT, attempt_id TEXT, type TEXT NOT NULL,
                  message TEXT, payload_json TEXT, created_at TEXT NOT NULL,
                  FOREIGN KEY(challenge_id) REFERENCES challenges(id),
                  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
                )
            """,
            """
                CREATE TABLE IF NOT EXISTS flag_candidates (
                  id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL, attempt_id TEXT,
                  value TEXT NOT NULL, source TEXT, confidence REAL, verified INTEGER NOT NULL DEFAULT 0,
                  created_at TEXT NOT NULL,
                  FOREIGN KEY(challenge_id) REFERENCES challenges(id),
                  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
                )
            """,
            """
                CREATE TABLE IF NOT EXISTS coordinator_leases (
                  contest TEXT PRIMARY KEY, owner TEXT NOT NULL, heartbeat_at TEXT NOT NULL,
                  expires_at TEXT NOT NULL
                )
            """,
            """
                CREATE TABLE IF NOT EXISTS attempt_leases (
                  challenge_id TEXT NOT NULL, profile TEXT NOT NULL, attempt_id TEXT NOT NULL UNIQUE,
                  owner TEXT NOT NULL, heartbeat_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                  PRIMARY KEY(challenge_id, profile),
                  FOREIGN KEY(challenge_id) REFERENCES challenges(id),
                  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
                )
            """,
            """
                CREATE TABLE IF NOT EXISTS outbox (
                  event_id TEXT PRIMARY KEY, event_json TEXT NOT NULL, created_at TEXT NOT NULL,
                  published_at TEXT, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT,
                  FOREIGN KEY(event_id) REFERENCES events(id)
                )
            """,
        )
        for statement in statements:
            conn.execute(statement)

    def _migrate_v1_to_v2(self, conn: sqlite3.Connection) -> None:
        """Apply the former additive changes as the first explicit upgrade."""
        self._add_column_if_missing(conn, "challenges", "synthetic", "INTEGER NOT NULL DEFAULT 0")
        self._add_column_if_missing(conn, "attempts", "synthetic", "INTEGER NOT NULL DEFAULT 0")
        self._add_column_if_missing(conn, "attempts", "cleanup_status", "TEXT")
        self._add_column_if_missing(conn, "attempts", "cleanup_message", "TEXT")
        self._add_column_if_missing(conn, "attempts", "lease_owner", "TEXT")
        self._add_column_if_missing(conn, "attempts", "fencing_token", "INTEGER")
        self._add_column_if_missing(conn, "events", "event_json", "TEXT")
        self._add_column_if_missing(conn, "flag_candidates", "verification_status", "TEXT NOT NULL DEFAULT 'CANDIDATE'")
        self._add_column_if_missing(conn, "flag_candidates", "verification_reason", "TEXT")
        self._add_column_if_missing(conn, "flag_candidates", "synthetic", "INTEGER NOT NULL DEFAULT 0")
        self._add_column_if_missing(conn, "attempt_leases", "fencing_token", "INTEGER NOT NULL DEFAULT 0")
        conn.execute("CREATE TABLE IF NOT EXISTS attempt_fence_tokens (token INTEGER PRIMARY KEY AUTOINCREMENT)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS model_cooldowns (
              model TEXT PRIMARY KEY, reason TEXT NOT NULL, expires_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            )
        """)
        for statement in (
            "CREATE INDEX IF NOT EXISTS idx_attempts_challenge ON attempts(challenge_id)",
            "CREATE INDEX IF NOT EXISTS idx_events_challenge ON events(challenge_id, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_flags_challenge ON flag_candidates(challenge_id, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_attempt_leases_expiry ON attempt_leases(expires_at)",
            "CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox(published_at, created_at)",
        ):
            conn.execute(statement)

    def _migrate_v2_to_v3(self, conn: sqlite3.Connection) -> None:
        """Make model cooldowns selection-aware without losing v2 cooldowns.

        Existing v2 records were keyed only by raw model, so they retain that
        intentionally broad meaning as ``model:<raw-model>`` records.  New
        routing selections use their own stable profile/model/effort keys and
        consult a legacy model-global record as an explicit override.
        """
        self._add_column_if_missing(conn, "attempts", "model_profile", "TEXT")
        self._add_column_if_missing(conn, "attempts", "reasoning_effort", "TEXT")
        columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(model_cooldowns)")}
        if "selection_key" not in columns:
            conn.execute("ALTER TABLE model_cooldowns RENAME TO model_cooldowns_v2")
            conn.execute("""
                CREATE TABLE model_cooldowns (
                  selection_key TEXT PRIMARY KEY, model TEXT NOT NULL, reason TEXT NOT NULL,
                  expires_at TEXT NOT NULL, updated_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                INSERT INTO model_cooldowns(selection_key, model, reason, expires_at, updated_at)
                SELECT 'model:' || model, model, reason, expires_at, updated_at
                FROM model_cooldowns_v2
            """)
            conn.execute("DROP TABLE model_cooldowns_v2")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_model_cooldowns_model_expiry "
            "ON model_cooldowns(model, expires_at)"
        )

    def _migrate_v3_to_v4(self, conn: sqlite3.Connection) -> None:
        """Persist optional Codex continuation identities on local attempts.

        These fields are deliberately nullable and additive: an existing
        attempt has no durable Codex session until a real backend result
        supplies one, while every v3 attempt row otherwise remains unchanged.
        """
        self._add_column_if_missing(conn, "attempts", "session_id", "TEXT")
        self._add_column_if_missing(conn, "attempts", "resume_id", "TEXT")

    def _migrate_v4_to_v5(self, conn: sqlite3.Connection) -> None:
        """Add stable cross-node challenge ownership without deleting history."""
        self._add_column_if_missing(conn, "challenges", "challenge_key", "TEXT")
        self._add_column_if_missing(conn, "events", "challenge_key", "TEXT")
        self._add_column_if_missing(conn, "flag_candidates", "challenge_key", "TEXT")
        rows = conn.execute("SELECT id, contest, category, name FROM challenges WHERE challenge_key IS NULL OR challenge_key='' ").fetchall()
        from .models import slugify
        for row in rows:
            key = ":".join((slugify(row["contest"]), slugify(row["category"]), slugify(row["name"])))
            conn.execute("UPDATE challenges SET challenge_key=? WHERE id=?", (key, row["id"]))
        conn.execute("UPDATE events SET challenge_key=(SELECT challenge_key FROM challenges WHERE challenges.id=events.challenge_id) WHERE challenge_key IS NULL")
        conn.execute("UPDATE flag_candidates SET challenge_key=(SELECT challenge_key FROM challenges WHERE challenges.id=flag_candidates.challenge_id) WHERE challenge_key IS NULL")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_challenges_challenge_key ON challenges(challenge_key)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_flag_candidates_challenge_value ON flag_candidates(challenge_id, value)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_attempts_challenge_id ON attempts(challenge_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_challenge_id_created_at ON events(challenge_id, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_flag_candidates_challenge_verified ON flag_candidates(challenge_id, verified, created_at)")

    @staticmethod
    def _migrate_v5_to_v6(conn: sqlite3.Connection) -> None:
        """Persist the authoritative team binding for challenge-key ownership.

        A legacy database cannot derive its team from challenge text.  The
        binding is therefore populated only when a caller supplies the local
        node's configured team ID, then retained for later opens.
        """
        conn.execute("""
            CREATE TABLE IF NOT EXISTS state_metadata (
              key TEXT PRIMARY KEY, value TEXT NOT NULL
            )
        """)

    @staticmethod
    def _migrate_v6_to_v7(conn: sqlite3.Connection) -> None:
        """Reserve metadata bindings for the local member and contest.

        The table was introduced in v6, so the migration itself is intentionally
        structural-no-op. Identity values are written only by
        :meth:`_bind_team_identity`, where the caller's complete config is
        available and mismatches can be rejected atomically.
        """
        conn.execute("""
            CREATE TABLE IF NOT EXISTS state_metadata (
              key TEXT PRIMARY KEY, value TEXT NOT NULL
            )
        """)

    @staticmethod
    def _migrate_v7_to_v8(conn: sqlite3.Connection) -> None:
        """Add durable Sol session and contract branch state."""
        conn.execute("""
            CREATE TABLE IF NOT EXISTS challenge_sessions (
              id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL UNIQUE,
              leader_model TEXT NOT NULL, leader_profile TEXT NOT NULL,
              reasoning_effort TEXT NOT NULL, status TEXT NOT NULL,
              leader_session_id TEXT, leader_resume_id TEXT,
              execution_contract_json TEXT NOT NULL, summary_state_json TEXT NOT NULL,
              generation INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              FOREIGN KEY(challenge_id) REFERENCES challenges(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS contract_tasks (
              id TEXT PRIMARY KEY, session_id TEXT NOT NULL, challenge_id TEXT NOT NULL,
              branch TEXT NOT NULL, role TEXT NOT NULL, objective TEXT NOT NULL,
              status TEXT NOT NULL, success_criteria_json TEXT NOT NULL,
              deliverables_json TEXT NOT NULL, failure_handoff TEXT,
              depends_on_json TEXT NOT NULL, assigned_attempt_id TEXT,
              result_summary TEXT, evidence_ids_json TEXT NOT NULL,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              FOREIGN KEY(session_id) REFERENCES challenge_sessions(id),
              FOREIGN KEY(challenge_id) REFERENCES challenges(id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_contract_tasks_session_status ON contract_tasks(session_id, status, created_at)")

    def _migrate_v8_to_v9(self, conn: sqlite3.Connection) -> None:
        """Persist complete branch execution specifications on durable tasks."""
        self._add_column_if_missing(conn, "contract_tasks", "backend", "TEXT NOT NULL DEFAULT 'codex'")
        self._add_column_if_missing(conn, "contract_tasks", "model_profile", "TEXT NOT NULL DEFAULT 'terra_high'")
        self._add_column_if_missing(conn, "contract_tasks", "reasoning_effort", "TEXT NOT NULL DEFAULT 'high'")
        self._add_column_if_missing(conn, "contract_tasks", "prompt_family", "TEXT NOT NULL DEFAULT 'implementation'")
        self._add_column_if_missing(conn, "contract_tasks", "timeout_sec", "INTEGER NOT NULL DEFAULT 1200")
        self._add_column_if_missing(conn, "contract_tasks", "tool_strategy", "TEXT NOT NULL DEFAULT 'exploit_build'")
        self._add_column_if_missing(conn, "contract_tasks", "priority", "INTEGER NOT NULL DEFAULT 50")
        conn.execute("""
            UPDATE contract_tasks SET
              model_profile=CASE WHEN role IN (
                'terra_high','terra_xhigh','luna_medium','luna_high','sol_high','sol_xhigh'
              ) THEN role ELSE model_profile END,
              reasoning_effort=CASE
                WHEN role IN ('terra_xhigh','sol_xhigh') THEN 'max'
                WHEN role='luna_medium' THEN 'medium'
                ELSE reasoning_effort END,
              prompt_family=CASE
                WHEN role LIKE 'luna_%' THEN 'recon'
                WHEN role='sol_xhigh' THEN 'takeover'
                WHEN role='sol_high' THEN 'deep_solve'
                ELSE prompt_family END
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_contract_tasks_priority "
            "ON contract_tasks(session_id, status, priority DESC, created_at)"
        )

    @staticmethod
    def _migrate_v9_to_v10(conn: sqlite3.Connection) -> None:
        """Persist tactical profiles, artifact provenance and rule idempotency."""
        conn.execute("""
            CREATE TABLE IF NOT EXISTS problem_profiles (
              challenge_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL,
              category TEXT NOT NULL, subtype TEXT NOT NULL, profile_json TEXT NOT NULL,
              confidence REAL NOT NULL, updated_at TEXT NOT NULL,
              FOREIGN KEY(challenge_id) REFERENCES challenges(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tactical_artifacts (
              id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL, attempt_id TEXT,
              contract_id TEXT, artifact_type TEXT NOT NULL, path TEXT NOT NULL,
              sha256 TEXT NOT NULL, parent_artifact_id TEXT, strategy_id TEXT NOT NULL,
              strategy_version INTEGER NOT NULL, creation_event_id TEXT,
              metadata_json TEXT NOT NULL, trust_state TEXT NOT NULL,
              consumers_json TEXT NOT NULL, created_at TEXT NOT NULL,
              FOREIGN KEY(challenge_id) REFERENCES challenges(id),
              FOREIGN KEY(attempt_id) REFERENCES attempts(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS replan_rule_fires (
              rule_id TEXT NOT NULL, event_id TEXT NOT NULL, challenge_id TEXT NOT NULL,
              fire_count INTEGER NOT NULL, fired_at TEXT NOT NULL,
              before_json TEXT NOT NULL, after_json TEXT NOT NULL,
              PRIMARY KEY(rule_id, event_id),
              FOREIGN KEY(challenge_id) REFERENCES challenges(id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tactical_artifacts_handoff ON tactical_artifacts(challenge_id, artifact_type, trust_state)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rule_fires_challenge ON replan_rule_fires(challenge_id, fired_at)")

    def _bind_team_identity(self, conn: sqlite3.Connection) -> None:
        """Bind node identity and normalize legacy keys without guessing ownership."""
        if not self._table_exists(conn, "state_metadata"):
            return
        metadata = {
            str(row["key"]): str(row["value"])
            for row in conn.execute(
                "SELECT key, value FROM state_metadata "
                "WHERE key IN ('team_id', 'member_name', 'contest_name')"
            )
        }
        stored_team_id = metadata.get("team_id")
        if self._team_id is not None and stored_team_id not in {None, self._team_id}:
            raise StateError(
                f"local-state database is bound to team {stored_team_id!r}, "
                f"not configured team {self._team_id!r}: {self.path}. "
                "This usually means paths.output points to another team's data; "
                "use that team's config or a separate output path."
            )

        self._require_matching_metadata(
            field="member.name", configured=self._member_name,
            stored=metadata.get("member_name"),
        )
        self._require_matching_metadata(
            field="contest.name", configured=self._contest_name,
            stored=metadata.get("contest_name"),
        )

        if self._member_name is not None and metadata.get("member_name") is None:
            evidence = self._legacy_event_members(conn)
            if len(evidence) == 1 and self._member_name not in evidence:
                stored_member = next(iter(evidence))
                raise StateError(
                    f"local-state identity mismatch at {self.path}: legacy event data "
                    f"belongs to member.name {stored_member!r}, but config member.name is "
                    f"{self._member_name!r}. Use the matching config or a separate output path."
                )

        if self._contest_name is not None and metadata.get("contest_name") is None:
            contests = {
                str(row["contest"])
                for row in conn.execute("SELECT DISTINCT contest FROM challenges")
            }
            if len(contests) == 1 and self._contest_name not in contests:
                stored_contest = next(iter(contests))
                raise StateError(
                    f"local-state identity mismatch at {self.path}: legacy challenge data "
                    f"belongs to contest.name {stored_contest!r}, but config contest.name is "
                    f"{self._contest_name!r}. Use the matching config or a separate output path."
                )

        for key, value in (
            ("team_id", self._team_id),
            ("member_name", self._member_name),
            ("contest_name", self._contest_name),
        ):
            if value is not None and key not in metadata:
                conn.execute(
                    "INSERT INTO state_metadata(key, value) VALUES (?, ?)",
                    (key, value),
                )

        authoritative_team_id = self._team_id or stored_team_id
        if authoritative_team_id is None:
            return
        self._bound_team_id = authoritative_team_id

        from .models import slugify
        rows = conn.execute(
            "SELECT id, contest, category, name, challenge_key FROM challenges"
        ).fetchall()
        for challenge in rows:
            suffix = ":".join((
                slugify(challenge["contest"]),
                slugify(challenge["category"]),
                slugify(challenge["name"]),
            ))
            legacy_key = str(challenge["challenge_key"] or "")
            expected_key = f"{authoritative_team_id}:{suffix}"
            if legacy_key in {"", suffix}:
                conn.execute(
                    "UPDATE challenges SET challenge_key=? WHERE id=?",
                    (expected_key, challenge["id"]),
                )
            elif legacy_key != expected_key:
                raise StateError(
                    f"challenge {challenge['id']!r} has key {legacy_key!r}, which "
                    f"does not belong to configured team {authoritative_team_id!r}"
                )

        conn.execute("""
            UPDATE events
            SET challenge_key=(
              SELECT challenges.challenge_key FROM challenges
              WHERE challenges.id=events.challenge_id
            )
            WHERE challenge_id IS NOT NULL
        """)
        conn.execute("""
            UPDATE flag_candidates
            SET challenge_key=(
              SELECT challenges.challenge_key FROM challenges
              WHERE challenges.id=flag_candidates.challenge_id
            )
            WHERE challenge_id IS NOT NULL
        """)
        event_rows = conn.execute("""
            SELECT events.id, events.event_json, challenges.challenge_key
            FROM events JOIN challenges ON challenges.id=events.challenge_id
            WHERE events.event_json IS NOT NULL AND events.event_json != ''
        """).fetchall()
        for event_row in event_rows:
            try:
                event_data = json.loads(str(event_row["event_json"]))
            except (TypeError, ValueError) as exc:
                raise StateError(
                    f"event {event_row['id']!r} contains invalid persisted JSON"
                ) from exc
            event_data["challenge_key"] = event_row["challenge_key"]
            encoded = json.dumps(
                event_data, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            conn.execute(
                "UPDATE events SET event_json=? WHERE id=?",
                (encoded, event_row["id"]),
            )
            conn.execute(
                "UPDATE outbox SET event_json=? WHERE event_id=?",
                (encoded, event_row["id"]),
            )

    def _require_matching_metadata(
        self,
        *,
        field: str,
        configured: str | None,
        stored: str | None,
    ) -> None:
        if configured is None or stored in {None, configured}:
            return
        raise StateError(
            f"local-state identity mismatch at {self.path}: database {field} is "
            f"{stored!r}, but config {field} is {configured!r}. This usually means "
            "the config was copied or edited while paths.output still points to another "
            "local node; use the matching config or a separate output path."
        )

    @staticmethod
    def _legacy_event_members(conn: sqlite3.Connection) -> set[str]:
        """Return unambiguous member evidence from pre-v7 persisted events."""
        members: set[str] = set()
        for row in conn.execute(
            "SELECT event_json FROM events WHERE event_json IS NOT NULL AND event_json != ''"
        ):
            try:
                data = json.loads(str(row["event_json"]))
            except (TypeError, ValueError):
                continue
            member = data.get("member") if isinstance(data, dict) else None
            if isinstance(member, str) and member.strip():
                members.add(member.strip())
        return members

    @staticmethod
    def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
        return conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone() is not None

    @staticmethod
    def _add_column_if_missing(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        columns = {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    # --- challenge and attempt state -------------------------------------------------

    def upsert_challenge(self, challenge: Challenge) -> Challenge:
        """Insert parsed metadata while preserving terminal/local workflow state."""
        challenge = self._challenge_for_bound_team(challenge)
        now = self._now()
        params = (
            challenge.id, challenge.contest, challenge.category, challenge.name, challenge.slug, challenge.challenge_key,
            challenge.score, challenge.remote, challenge.description, challenge.hint,
            challenge.flag_format, challenge.flag_pattern, challenge.status.value,
            challenge.assignee, challenge.flag, int(challenge.synthetic), timestamp_text(challenge.created_at), now,
        )
        with self._write() as conn:
            conn.execute("""
                INSERT INTO challenges (
                  id, contest, category, name, slug, challenge_key, score, remote, description, hint,
                  flag_format, flag_pattern, status, assignee, flag, synthetic, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  contest=excluded.contest, category=excluded.category, name=excluded.name,
                  slug=excluded.slug, challenge_key=excluded.challenge_key, score=excluded.score, remote=excluded.remote,
                  description=excluded.description, hint=excluded.hint,
                  flag_format=excluded.flag_format, flag_pattern=excluded.flag_pattern,
                  updated_at=excluded.updated_at
            """, params)
        return self.get_challenge(challenge.id)  # type: ignore[return-value]

    def _challenge_for_bound_team(self, challenge: Challenge) -> Challenge:
        """Apply only the persisted/configured team identity to a parsed key."""
        if self._bound_team_id is None:
            return challenge
        from .models import slugify
        suffix = ":".join((
            slugify(challenge.contest), slugify(challenge.category), slugify(challenge.name)
        ))
        expected = f"{self._bound_team_id}:{suffix}"
        if challenge.challenge_key == suffix:
            return replace(challenge, challenge_key=expected)
        if challenge.challenge_key != expected:
            raise StateError(
                f"challenge {challenge.id!r} has key {challenge.challenge_key!r}, which "
                f"does not belong to configured team {self._bound_team_id!r}"
            )
        return challenge

    def upsert_challenges(self, challenges: Iterable[Challenge]) -> list[Challenge]:
        return [self.upsert_challenge(challenge) for challenge in challenges]

    def get_challenge(self, challenge_id: str) -> Challenge | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM challenges WHERE id = ?", (challenge_id,)).fetchone()
        return _challenge_from_row(row) if row else None

    def list_challenges(self, *, contest: str | None = None, status: ChallengeStatus | str | None = None) -> list[Challenge]:
        query = "SELECT * FROM challenges"
        values: list[Any] = []
        clauses: list[str] = []
        if contest is not None:
            clauses.append("contest = ?")
            values.append(contest)
        if status is not None:
            clauses.append("status = ?")
            values.append(_status_text(status))
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY contest, category, name"
        with self._connect() as conn:
            rows = conn.execute(query, values).fetchall()
        return [_challenge_from_row(row) for row in rows]

    def transition_challenge_status(
        self,
        challenge_id: str,
        new_status: ChallengeStatus | str,
        *,
        flag: str | None = None,
        synthetic: bool | None = None,
        event: Event | None = None,
        attempt_id: str | None = None,
        owner: str | None = None,
        fencing_token: int | None = None,
        now: datetime | str | None = None,
    ) -> Challenge:
        desired = ChallengeStatus(_status_text(new_status))
        with self._write() as conn:
            if attempt_id is not None:
                self._require_active_attempt_lease_conn(conn, attempt_id, owner, fencing_token, now=now)
            elif desired in {ChallengeStatus.RUNNING, ChallengeStatus.FLAG_CANDIDATE, ChallengeStatus.VERIFYING, ChallengeStatus.SOLVED}:
                raise StateTransitionError("authoritative challenge transitions require an active attempt lease")
            row = conn.execute("SELECT status, flag, synthetic FROM challenges WHERE id = ?", (challenge_id,)).fetchone()
            if row is None:
                raise KeyError(f"unknown challenge: {challenge_id}")
            current = ChallengeStatus(row["status"])
            if current is ChallengeStatus.SOLVED:
                if desired is not ChallengeStatus.SOLVED or (flag is not None and flag != row["flag"]):
                    raise StateTransitionError("SOLVED is immutable")
            else:
                if desired != current and desired not in _TRANSITIONS[current]:
                    raise StateTransitionError(f"invalid challenge transition: {current} -> {desired}")
                if flag is not None and desired is not ChallengeStatus.SOLVED:
                    raise StateTransitionError("a confirmed flag can only be stored when marking SOLVED")
                if synthetic is not None and desired is not ChallengeStatus.SOLVED:
                    raise StateTransitionError("synthetic marker is only valid for a solved result")
                conn.execute(
                    "UPDATE challenges SET status = ?, flag = COALESCE(?, flag), synthetic = COALESCE(?, synthetic), updated_at = ? WHERE id = ?",
                    (desired.value, flag, int(synthetic) if synthetic is not None else None, self._now(now), challenge_id),
                )
            if event is not None:
                self._record_event_conn(conn, event)
        return self.get_challenge(challenge_id)  # type: ignore[return-value]

    transition_challenge = transition_challenge_status

    # --- persistent challenge sessions and contract branches -----------------------

    def upsert_challenge_session(self, session: ChallengeSession) -> ChallengeSession:
        """Create or checkpoint the single persistent controller for a challenge."""
        with self._write() as conn:
            if conn.execute("SELECT 1 FROM challenges WHERE id=?", (session.challenge_id,)).fetchone() is None:
                raise KeyError(f"unknown challenge: {session.challenge_id}")
            conn.execute("""
                INSERT INTO challenge_sessions (
                  id, challenge_id, leader_model, leader_profile, reasoning_effort,
                  status, leader_session_id, leader_resume_id, execution_contract_json,
                  summary_state_json, generation, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(challenge_id) DO UPDATE SET
                  leader_model=excluded.leader_model, leader_profile=excluded.leader_profile,
                  reasoning_effort=excluded.reasoning_effort, status=excluded.status,
                  leader_session_id=COALESCE(excluded.leader_session_id, challenge_sessions.leader_session_id),
                  leader_resume_id=COALESCE(excluded.leader_resume_id, challenge_sessions.leader_resume_id),
                  execution_contract_json=excluded.execution_contract_json,
                  summary_state_json=excluded.summary_state_json,
                  generation=excluded.generation, updated_at=excluded.updated_at
            """, _challenge_session_values(session))
        return self.get_challenge_session(session.challenge_id)  # type: ignore[return-value]

    def get_or_create_challenge_session(
        self,
        challenge_id: str,
        *,
        leader_model: str,
        leader_profile: str = "sol",
        reasoning_effort: str = "xhigh",
        execution_contract: dict[str, Any] | None = None,
    ) -> ChallengeSession:
        existing = self.get_challenge_session(challenge_id)
        if existing is not None:
            return existing
        return self.upsert_challenge_session(ChallengeSession(
            challenge_id=challenge_id, leader_model=leader_model,
            leader_profile=leader_profile, reasoning_effort=reasoning_effort,
            execution_contract=execution_contract or {},
        ))

    def checkpoint_challenge_session(
        self,
        challenge_id: str,
        *,
        summary_state: dict[str, Any] | None = None,
        execution_contract: dict[str, Any] | None = None,
        leader_session_id: str | None = None,
        leader_resume_id: str | None = None,
        status: SessionStatus | str | None = None,
        advance_generation: bool = False,
    ) -> ChallengeSession:
        """Checkpoint Sol continuation and distilled state between controller cycles."""
        current = self.get_challenge_session(challenge_id)
        if current is None:
            raise KeyError(f"unknown challenge session: {challenge_id}")
        return self.upsert_challenge_session(replace(
            current,
            summary_state=current.summary_state if summary_state is None else summary_state,
            execution_contract=current.execution_contract if execution_contract is None else execution_contract,
            leader_session_id=leader_session_id or current.leader_session_id,
            leader_resume_id=leader_resume_id or current.leader_resume_id,
            status=current.status if status is None else status,
            generation=current.generation + int(advance_generation),
            updated_at=ensure_utc(self._clock()),
        ))

    def get_challenge_session(self, challenge_id: str) -> ChallengeSession | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM challenge_sessions WHERE challenge_id=?", (challenge_id,)
            ).fetchone()
        return _challenge_session_from_row(row) if row else None

    def list_challenge_sessions(self, *, status: str | None = None) -> list[ChallengeSession]:
        query = "SELECT * FROM challenge_sessions"
        values: tuple[Any, ...] = ()
        if status is not None:
            query += " WHERE status=?"
            values = (str(status).upper(),)
        query += " ORDER BY created_at, id"
        with self._connect() as conn:
            rows = conn.execute(query, values).fetchall()
        return [_challenge_session_from_row(row) for row in rows]

    def upsert_contract_task(self, task: ContractTask) -> ContractTask:
        """Persist a controller-issued branch and its eventual handoff result."""
        with self._write() as conn:
            session = conn.execute(
                "SELECT challenge_id FROM challenge_sessions WHERE id=?", (task.session_id,)
            ).fetchone()
            if session is None:
                raise KeyError(f"unknown challenge session: {task.session_id}")
            if str(session["challenge_id"]) != task.challenge_id:
                raise StateTransitionError("contract task challenge does not match its session")
            existing = conn.execute(
                "SELECT session_id, challenge_id, branch FROM contract_tasks WHERE id=?", (task.id,)
            ).fetchone()
            if existing is not None and (
                str(existing["session_id"]), str(existing["challenge_id"]), str(existing["branch"])
            ) != (task.session_id, task.challenge_id, task.branch):
                raise StateTransitionError("contract task identity cannot be rebound")
            conn.execute("""
                INSERT INTO contract_tasks (
                  id, session_id, challenge_id, branch, role, objective, status,
                  backend, model_profile, reasoning_effort, prompt_family, timeout_sec,
                  tool_strategy, priority,
                  success_criteria_json, deliverables_json, failure_handoff,
                  depends_on_json, assigned_attempt_id, result_summary,
                  evidence_ids_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  branch=excluded.branch, role=excluded.role, objective=excluded.objective,
                  backend=excluded.backend, model_profile=excluded.model_profile,
                  reasoning_effort=excluded.reasoning_effort,
                  prompt_family=excluded.prompt_family, timeout_sec=excluded.timeout_sec,
                  tool_strategy=excluded.tool_strategy, priority=excluded.priority,
                  success_criteria_json=excluded.success_criteria_json,
                  deliverables_json=excluded.deliverables_json,
                  failure_handoff=excluded.failure_handoff,
                  depends_on_json=excluded.depends_on_json,
                  updated_at=excluded.updated_at
            """, _contract_task_values(task))
        return self.get_contract_task(task.id)  # type: ignore[return-value]

    def get_contract_task(self, task_id: str) -> ContractTask | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM contract_tasks WHERE id=?", (task_id,)).fetchone()
        return _contract_task_from_row(row) if row else None

    def mark_contract_task_outcome(
        self,
        task_id: str,
        *,
        status: ContractTaskStatus | str,
        result_summary: str | None = None,
        evidence_ids: Iterable[str] = (),
        assigned_attempt_id: str | None = None,
    ) -> ContractTask:
        current = self.get_contract_task(task_id)
        if current is None:
            raise KeyError(f"unknown contract task: {task_id}")
        desired = status if isinstance(status, ContractTaskStatus) else ContractTaskStatus(str(status).upper())
        allowed = {
            ContractTaskStatus.PENDING: {ContractTaskStatus.RUNNING, ContractTaskStatus.SUCCEEDED, ContractTaskStatus.CANCELLED, ContractTaskStatus.FAILED, ContractTaskStatus.PAUSED},
            ContractTaskStatus.RUNNING: {ContractTaskStatus.SUCCEEDED, ContractTaskStatus.FAILED, ContractTaskStatus.CANCELLED, ContractTaskStatus.PAUSED},
            ContractTaskStatus.SUCCEEDED: set(), ContractTaskStatus.FAILED: set(),
            ContractTaskStatus.CANCELLED: set(),
            ContractTaskStatus.PAUSED: {ContractTaskStatus.PENDING, ContractTaskStatus.RUNNING, ContractTaskStatus.CANCELLED},
        }
        if desired is not current.status and desired not in allowed[current.status]:
            raise StateTransitionError(f"invalid contract task transition: {current.status} -> {desired}")
        durable_evidence = tuple(evidence_ids) or current.evidence_ids
        with self._write() as conn:
            conn.execute(
                "UPDATE contract_tasks SET status=?, result_summary=COALESCE(?, result_summary), "
                "evidence_ids_json=?, assigned_attempt_id=COALESCE(?, assigned_attempt_id), updated_at=? WHERE id=?",
                (desired.value, result_summary, _json_value(durable_evidence), assigned_attempt_id,
                 self._now(), task_id),
            )
        return self.get_contract_task(task_id)  # type: ignore[return-value]

    def list_contract_tasks(
        self, session_id: str, *, status: ContractTaskStatus | str | None = None,
    ) -> list[ContractTask]:
        query = "SELECT * FROM contract_tasks WHERE session_id=?"
        values: list[Any] = [session_id]
        if status is not None:
            query += " AND status=?"
            values.append(status.value if isinstance(status, ContractTaskStatus) else str(status).upper())
        query += " ORDER BY created_at, id"
        with self._connect() as conn:
            rows = conn.execute(query, values).fetchall()
        return [_contract_task_from_row(row) for row in rows]

    def upsert_attempt(self, attempt: Attempt, *, owner: str | None = None, fencing_token: int | None = None,
                       now: datetime | str | None = None) -> Attempt:
        with self._write() as conn:
            existing = conn.execute("SELECT 1 FROM attempts WHERE id=?", (attempt.id,)).fetchone()
            if existing is not None:
                self._require_active_attempt_lease_conn(conn, attempt.id, owner, fencing_token, now=now)
            elif owner is not None or fencing_token is not None:
                raise StateTransitionError("new attempts must be created by claim_attempt")
            self._upsert_attempt_conn(conn, attempt)
        return self.get_attempt(attempt.id)  # type: ignore[return-value]

    create_attempt = upsert_attempt

    @staticmethod
    def _upsert_attempt_conn(conn: sqlite3.Connection, attempt: Attempt) -> None:
        conn.execute("""
            INSERT INTO attempts (
              id, challenge_id, profile, role, backend, model, model_profile, reasoning_effort, pid, container_name,
              session_id, resume_id, workdir, status, started_at, ended_at, token_total, synthetic, cleanup_status, cleanup_message, lease_owner, fencing_token
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              profile=excluded.profile, role=excluded.role, backend=excluded.backend,
              model=excluded.model, model_profile=excluded.model_profile, reasoning_effort=excluded.reasoning_effort,
              pid=excluded.pid, container_name=excluded.container_name,
              session_id=COALESCE(excluded.session_id, attempts.session_id),
              resume_id=COALESCE(excluded.resume_id, attempts.resume_id),
              workdir=excluded.workdir, status=excluded.status, started_at=excluded.started_at,
              ended_at=excluded.ended_at, token_total=excluded.token_total,
              synthetic=excluded.synthetic, cleanup_status=excluded.cleanup_status,
              cleanup_message=excluded.cleanup_message, lease_owner=excluded.lease_owner,
              fencing_token=excluded.fencing_token
        """, _attempt_values(attempt))

    def get_attempt(self, attempt_id: str) -> Attempt | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM attempts WHERE id = ?", (attempt_id,)).fetchone()
        return _attempt_from_row(row) if row else None

    def list_attempts(self, challenge_id: str) -> list[Attempt]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM attempts WHERE challenge_id = ? ORDER BY id", (challenge_id,)).fetchall()
        return [_attempt_from_row(row) for row in rows]

    def finish_attempt(
        self,
        attempt_id: str,
        status: AttemptStatus | str,
        *,
        token_total: int | None = None,
        cleanup_status: str | None = None,
        cleanup_message: str | None = None,
        event: Event | None = None,
        owner: str | None = None,
        fencing_token: int | None = None,
        now: datetime | str | None = None,
    ) -> Attempt:
        status_text = status.value if isinstance(status, AttemptStatus) else str(status).upper()
        with self._write() as conn:
            self._require_active_attempt_lease_conn(conn, attempt_id, owner, fencing_token, now=now)
            row = conn.execute("SELECT token_total FROM attempts WHERE id = ?", (attempt_id,)).fetchone()
            if row is None:
                raise KeyError(f"unknown attempt: {attempt_id}")
            conn.execute(
                "UPDATE attempts SET status=?, ended_at=?, token_total=?, cleanup_status=COALESCE(?, cleanup_status), cleanup_message=COALESCE(?, cleanup_message) WHERE id=?",
                (status_text, self._now(now), int(token_total if token_total is not None else row["token_total"]), cleanup_status, cleanup_message, attempt_id),
            )
            conn.execute("DELETE FROM attempt_leases WHERE attempt_id = ?", (attempt_id,))
            if event is not None:
                self._record_event_conn(conn, event)
        return self.get_attempt(attempt_id)  # type: ignore[return-value]

    def record_attempt_session_ids(
        self,
        attempt_id: str,
        *,
        session_id: str | None = None,
        resume_id: str | None = None,
        owner: str | None,
        fencing_token: int | None,
        now: datetime | str | None = None,
    ) -> Attempt:
        """Persist real Codex continuation IDs only for the live lease.

        A backend may only report one of the two values.  Missing values must
        not erase an earlier captured ID from the same attempt, particularly
        when a configured model fallback starts a second Codex invocation.
        """
        if session_id is None and resume_id is None:
            raise ValueError("at least one Codex session identifier is required")
        for label, value in (("session_id", session_id), ("resume_id", resume_id)):
            if value is not None and (not isinstance(value, str) or not value):
                raise ValueError(f"{label} must be a non-empty string when set")
        with self._write() as conn:
            self._require_active_attempt_lease_conn(conn, attempt_id, owner, fencing_token, now=now)
            row = conn.execute("SELECT 1 FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            if row is None:
                raise KeyError(f"unknown attempt: {attempt_id}")
            conn.execute(
                "UPDATE attempts SET session_id=COALESCE(?, session_id), resume_id=COALESCE(?, resume_id) WHERE id=?",
                (session_id, resume_id, attempt_id),
            )
        return self.get_attempt(attempt_id)  # type: ignore[return-value]

    def record_cleanup(self, attempt_id: str, *, ok: bool, detail: str = "") -> Attempt:
        with self._write() as conn:
            if conn.execute("SELECT 1 FROM attempts WHERE id = ?", (attempt_id,)).fetchone() is None:
                raise KeyError(f"unknown attempt: {attempt_id}")
            conn.execute(
                "UPDATE attempts SET cleanup_status=?, cleanup_message=? WHERE id=?",
                ("CLEANED" if ok else "CLEANUP_FAILED", detail or None, attempt_id),
            )
        return self.get_attempt(attempt_id)  # type: ignore[return-value]

    # --- process-safe scheduling ------------------------------------------------------

    def claim_coordinator(
        self, *, contest: str, owner: str, lease_seconds: float, now: datetime | str | None = None
    ) -> LeaseClaim:
        if not contest or not owner or lease_seconds <= 0:
            raise ValueError("contest, owner, and a positive lease duration are required")
        timestamp = ensure_utc(now if now is not None else self._clock())
        now_text = timestamp_text(timestamp)
        from datetime import timedelta
        expiry = timestamp_text(timestamp + timedelta(seconds=lease_seconds))
        with self._write() as conn:
            row = conn.execute("SELECT owner, expires_at FROM coordinator_leases WHERE contest=?", (contest,)).fetchone()
            if row is not None and row["owner"] != owner and row["expires_at"] > now_text:
                return LeaseClaim(False, "another local coordinator holds an unexpired lease")
            conn.execute(
                "INSERT INTO coordinator_leases(contest, owner, heartbeat_at, expires_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(contest) DO UPDATE SET owner=excluded.owner, heartbeat_at=excluded.heartbeat_at, expires_at=excluded.expires_at",
                (contest, owner, now_text, expiry),
            )
        return LeaseClaim(True)

    def heartbeat_coordinator(
        self, *, contest: str, owner: str, lease_seconds: float, now: datetime | str | None = None
    ) -> bool:
        if lease_seconds <= 0:
            raise ValueError("lease duration must be positive")
        from datetime import timedelta
        timestamp = ensure_utc(now if now is not None else self._clock())
        now_text = timestamp_text(timestamp)
        with self._write() as conn:
            updated = conn.execute(
                "UPDATE coordinator_leases SET heartbeat_at=?, expires_at=? WHERE contest=? AND owner=? AND expires_at>?",
                (timestamp_text(timestamp), timestamp_text(timestamp + timedelta(seconds=lease_seconds)), contest, owner, now_text),
            ).rowcount
        return bool(updated)

    def release_coordinator(self, *, contest: str, owner: str) -> None:
        with self._write() as conn:
            conn.execute("DELETE FROM coordinator_leases WHERE contest=? AND owner=?", (contest, owner))

    def claim_attempt(
        self,
        attempt: Attempt,
        *,
        owner: str,
        lease_seconds: float,
        max_workers_total: int,
        max_workers_per_challenge: int,
        now: datetime | str | None = None,
    ) -> LeaseClaim:
        """Atomically reserve an attempt profile and both configured capacities."""
        if not owner or lease_seconds <= 0 or max_workers_total < 1 or max_workers_per_challenge < 1:
            raise ValueError("owner, positive lease, and positive worker limits are required")
        from datetime import timedelta
        timestamp = ensure_utc(now if now is not None else self._clock())
        now_text = timestamp_text(timestamp)
        expiry = timestamp_text(timestamp + timedelta(seconds=lease_seconds))
        with self._write() as conn:
            # Reconciliation occurs in the same transaction as a replacement
            # claim: an expired owner is stopped/requeued before a new token is
            # issued, so no challenge remains stuck RUNNING.
            self._reconcile_expired_attempts_conn(conn, now_text)
            challenge = conn.execute("SELECT status FROM challenges WHERE id=?", (attempt.challenge_id,)).fetchone()
            if challenge is None:
                raise KeyError(f"unknown challenge: {attempt.challenge_id}")
            if ChallengeStatus(challenge["status"]) is ChallengeStatus.SOLVED:
                return LeaseClaim(False, "challenge is already solved")
            existing = conn.execute(
                "SELECT owner, attempt_id, expires_at, fencing_token FROM attempt_leases WHERE challenge_id=? AND profile=?",
                (attempt.challenge_id, attempt.profile),
            ).fetchone()
            if existing is not None and (existing["owner"] != owner or existing["attempt_id"] != attempt.id):
                return LeaseClaim(False, "attempt profile already claimed locally")
            total = int(conn.execute("SELECT COUNT(*) AS count FROM attempt_leases WHERE expires_at > ?", (now_text,)).fetchone()["count"])
            per_challenge = int(conn.execute(
                "SELECT COUNT(*) AS count FROM attempt_leases WHERE challenge_id=? AND expires_at > ?",
                (attempt.challenge_id, now_text),
            ).fetchone()["count"])
            # Retrying the same reservation must not consume capacity twice.
            same_reservation = existing is not None
            if not same_reservation and total >= max_workers_total:
                return LeaseClaim(False, "global local worker lease capacity reached")
            if not same_reservation and per_challenge >= max_workers_per_challenge:
                return LeaseClaim(False, "per-challenge local worker lease capacity reached")
            if existing is not None:
                token = int(existing["fencing_token"])
            else:
                token = int(conn.execute("INSERT INTO attempt_fence_tokens DEFAULT VALUES").lastrowid)
            leased_attempt = replace(attempt, lease_owner=owner, fencing_token=token)
            self._upsert_attempt_conn(conn, leased_attempt)
            conn.execute(
                "INSERT INTO attempt_leases(challenge_id, profile, attempt_id, owner, fencing_token, heartbeat_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(challenge_id, profile) DO UPDATE SET attempt_id=excluded.attempt_id, owner=excluded.owner, fencing_token=excluded.fencing_token, heartbeat_at=excluded.heartbeat_at, expires_at=excluded.expires_at",
                (attempt.challenge_id, attempt.profile, attempt.id, owner, token, now_text, expiry),
            )
        return LeaseClaim(True, fencing_token=token)

    def heartbeat_attempt(self, *, attempt_id: str, owner: str, fencing_token: int, lease_seconds: float, now: datetime | str | None = None) -> bool:
        if lease_seconds <= 0:
            raise ValueError("lease duration must be positive")
        from datetime import timedelta
        timestamp = ensure_utc(now if now is not None else self._clock())
        now_text = timestamp_text(timestamp)
        with self._write() as conn:
            updated = conn.execute(
                "UPDATE attempt_leases SET heartbeat_at=?, expires_at=? WHERE attempt_id=? AND owner=? AND fencing_token=? AND expires_at>?",
                (now_text, timestamp_text(timestamp + timedelta(seconds=lease_seconds)), attempt_id, owner, fencing_token, now_text),
            ).rowcount
        return bool(updated)

    def reconcile_stale_attempts(
        self, *, now: datetime | str | None = None,
        recovery_event_factory: Callable[[str, str, str, int], Event] | None = None,
    ) -> RecoveryResult:
        """Fence stale attempts, retain candidates, and requeue recoverable work.

        Recovery lifecycle events are inserted in the same transaction as the
        lease deletion/state transition when a factory is supplied.  They carry
        the old fencing token, making the local event explanation attributable to
        the exact lease that died rather than a later replacement worker.
        """
        now_text = self._now(now)
        with self._write() as conn:
            stale_rows = conn.execute(
                "SELECT attempt_id, challenge_id, fencing_token FROM attempt_leases WHERE expires_at <= ? ORDER BY attempt_id",
                (now_text,),
            ).fetchall()
            stale_ids, requeued = self._reconcile_expired_attempts_conn(conn, now_text)
            if recovery_event_factory is not None:
                by_challenge = {str(row["challenge_id"]): row for row in stale_rows}
                for row in stale_rows:
                    self._record_event_conn(conn, recovery_event_factory(
                        "WORKER_STOPPED", str(row["attempt_id"]), str(row["challenge_id"]), int(row["fencing_token"]),
                    ))
                for challenge_id in requeued:
                    row = by_challenge[challenge_id]
                    self._record_event_conn(conn, recovery_event_factory(
                        "QUEUED", str(row["attempt_id"]), challenge_id, int(row["fencing_token"]),
                    ))
        return RecoveryResult(stale_ids, tuple(requeued))

    @staticmethod
    def _reconcile_expired_attempts_conn(conn: sqlite3.Connection, now_text: str) -> tuple[tuple[str, ...], list[str]]:
        stale_rows = conn.execute("SELECT attempt_id, challenge_id FROM attempt_leases WHERE expires_at <= ?", (now_text,)).fetchall()
        stale_ids = tuple(str(row["attempt_id"]) for row in stale_rows)
        challenge_ids = tuple(dict.fromkeys(str(row["challenge_id"]) for row in stale_rows))
        if stale_ids:
            conn.executemany(
                "UPDATE attempts SET status=?, ended_at=?, cleanup_status=COALESCE(cleanup_status, ?) WHERE id=? AND status IN (?, ?)",
                [(AttemptStatus.STOPPED.value, now_text, "RECOVERY_PENDING", item, AttemptStatus.QUEUED.value, AttemptStatus.RUNNING.value) for item in stale_ids],
            )
            conn.executemany(
                "UPDATE flag_candidates SET verification_status='UNAVAILABLE', verification_reason=? "
                "WHERE attempt_id=? AND verification_status IN ('RAW_CANDIDATE', 'CANDIDATE', 'VERIFYING', 'UNAVAILABLE')",
                [("attempt lease expired; candidate remains retryable", item) for item in stale_ids],
            )
            conn.executemany(
                "UPDATE contract_tasks SET status='FAILED', result_summary=?, updated_at=? "
                "WHERE assigned_attempt_id=? AND status IN ('PENDING', 'RUNNING')",
                [("assigned attempt lease expired; Sol must replan", now_text, item) for item in stale_ids],
            )
            conn.execute("DELETE FROM attempt_leases WHERE expires_at <= ?", (now_text,))
        requeued: list[str] = []
        for challenge_id in challenge_ids:
            active = conn.execute("SELECT 1 FROM attempt_leases WHERE challenge_id=? AND expires_at>? LIMIT 1", (challenge_id, now_text)).fetchone()
            row = conn.execute("SELECT status FROM challenges WHERE id=?", (challenge_id,)).fetchone()
            if row is not None and not active and row["status"] in {
                ChallengeStatus.RUNNING.value, ChallengeStatus.FLAG_CANDIDATE.value, ChallengeStatus.VERIFYING.value,
            }:
                conn.execute("UPDATE challenges SET status=?, updated_at=? WHERE id=?", (ChallengeStatus.QUEUED.value, now_text, challenge_id))
                conn.execute(
                    "UPDATE contract_tasks SET status='CANCELLED', result_summary=COALESCE(result_summary, ?), updated_at=? "
                    "WHERE challenge_id=? AND status='PENDING'",
                    ("local coordinator recovery requeued challenge", now_text, challenge_id),
                )
                requeued.append(challenge_id)
        return stale_ids, requeued

    def _require_active_attempt_lease_conn(
        self, conn: sqlite3.Connection, attempt_id: str, owner: str | None, fencing_token: int | None,
        *, now: datetime | str | None,
    ) -> None:
        if not owner or fencing_token is None or fencing_token < 1:
            raise StateTransitionError("active attempt lease owner and fencing token are required")
        now_text = self._now(now)
        row = conn.execute(
            "SELECT 1 FROM attempt_leases WHERE attempt_id=? AND owner=? AND fencing_token=? AND expires_at>?",
            (attempt_id, owner, fencing_token, now_text),
        ).fetchone()
        if row is None:
            raise StateTransitionError("attempt lease is missing, expired, or fenced by a newer owner")

    def active_container_names(self, *, now: datetime | str | None = None) -> tuple[str, ...]:
        now_text = self._now(now)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT a.container_name FROM attempts a JOIN attempt_leases l ON l.attempt_id=a.id "
                "WHERE l.expires_at>? AND a.container_name IS NOT NULL ORDER BY a.container_name",
                (now_text,),
            ).fetchall()
        return tuple(str(row["container_name"]) for row in rows)

    def active_attempt_ids(self, *, now: datetime | str | None = None) -> tuple[str, ...]:
        """Lease-backed local attempt IDs, for label-scoped Docker recovery."""
        now_text = self._now(now)
        with self._connect() as conn:
            rows = conn.execute("SELECT attempt_id FROM attempt_leases WHERE expires_at>? ORDER BY attempt_id", (now_text,)).fetchall()
        return tuple(str(row["attempt_id"]) for row in rows)

    def get_active_attempt(self, attempt_id: str, *, now: datetime | str | None = None) -> Attempt | None:
        """Return an attempt only while its exact recorded lease is live.

        This is used by the direct sandbox CLI.  It intentionally does not
        accept a remembered container name alone: an expired/reassigned row
        must never grant a fresh host-side Docker exec capability.
        """
        now_text = self._now(now)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT a.* FROM attempts a JOIN attempt_leases l ON l.attempt_id=a.id "
                "WHERE a.id=? AND l.expires_at>? AND a.lease_owner=l.owner AND a.fencing_token=l.fencing_token",
                (attempt_id, now_text),
            ).fetchone()
        return _attempt_from_row(row) if row else None

    # --- events, candidates, and durable outbox --------------------------------------

    @staticmethod
    def _record_event_conn(conn: sqlite3.Connection, event: Event) -> None:
        encoded_payload = json.dumps(dict(event.payload), ensure_ascii=False, sort_keys=True)
        encoded_event = json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        conn.execute(
            "INSERT OR IGNORE INTO events (id, challenge_id, challenge_key, attempt_id, type, message, payload_json, event_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (event.id, event.challenge_id, event.challenge_key, event.attempt_id, event.type, event.message, encoded_payload, encoded_event, timestamp_text(event.timestamp)),
        )
        conn.execute(
            "INSERT OR IGNORE INTO outbox(event_id, event_json, created_at) VALUES (?, ?, ?)",
            (event.id, encoded_event, timestamp_text(event.timestamp)),
        )

    def append_event(self, event: Event) -> Event:
        with self._write() as conn:
            self._record_event_conn(conn, event)
        self._notify_committed_events((event,))
        return event

    record_event = append_event

    def upsert_problem_profile(self, challenge_id: str, profile: Mapping[str, Any]) -> dict[str, Any]:
        """Persist one versioned profile atomically for incremental classification."""
        version = profile.get("schema_version", 1)
        if version != 1:
            raise StateError(f"unsupported problem profile schema version {version}")
        category, subtype = str(profile.get("category", "")), str(profile.get("subtype", ""))
        confidence = profile.get("confidence", 0.0)
        if not category or not subtype or isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            raise ValueError("profile requires category, subtype and confidence in [0,1]")
        payload = json.dumps(dict(profile), ensure_ascii=False, sort_keys=True)
        with self._write() as conn:
            conn.execute(
                "INSERT INTO problem_profiles(challenge_id,schema_version,category,subtype,profile_json,confidence,updated_at) "
                "VALUES (?,?,?,?,?,?,?) ON CONFLICT(challenge_id) DO UPDATE SET schema_version=excluded.schema_version,"
                "category=excluded.category,subtype=excluded.subtype,profile_json=excluded.profile_json,"
                "confidence=excluded.confidence,updated_at=excluded.updated_at",
                (challenge_id, version, category, subtype, payload, float(confidence), self._now()),
            )
        return dict(profile)

    def get_problem_profile(self, challenge_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT profile_json FROM problem_profiles WHERE challenge_id=?", (challenge_id,)).fetchone()
        return json.loads(row["profile_json"]) if row else None

    def record_rule_fire(
        self, *, rule_id: str, event_id: str, challenge_id: str,
        before: Mapping[str, Any], after: Mapping[str, Any],
    ) -> bool:
        """Return False for an idempotent duplicate rule/event pair."""
        with self._write() as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO replan_rule_fires(rule_id,event_id,challenge_id,fire_count,fired_at,before_json,after_json) "
                "VALUES (?,?,?,?,?,?,?)",
                (rule_id, event_id, challenge_id, 1, self._now(),
                 json.dumps(dict(before), sort_keys=True), json.dumps(dict(after), sort_keys=True)),
            )
            return cursor.rowcount == 1

    def record_tactical_artifact(self, manifest: Mapping[str, Any]) -> dict[str, Any]:
        required = {"id", "challenge_id", "artifact_type", "path", "sha256", "strategy_id", "strategy_version"}
        missing = required - set(manifest)
        if missing:
            raise ValueError(f"artifact manifest missing: {', '.join(sorted(missing))}")
        values = dict(manifest)
        with self._write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO tactical_artifacts(id,challenge_id,attempt_id,contract_id,artifact_type,path,sha256,"
                "parent_artifact_id,strategy_id,strategy_version,creation_event_id,metadata_json,trust_state,consumers_json,created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (values["id"], values["challenge_id"], values.get("attempt_id"), values.get("contract_id"),
                 values["artifact_type"], values["path"], values["sha256"], values.get("parent_artifact_id"),
                 values["strategy_id"], values["strategy_version"], values.get("creation_event_id"),
                 json.dumps(values.get("content_metadata", {}), sort_keys=True), values.get("trust_state", "unverified"),
                 json.dumps(values.get("consumers", []), sort_keys=True), self._now()),
            )
        return values

    def promote_tactical_artifacts(
        self, challenge_id: str, artifact_type: str, *, consumer: str | None = None,
    ) -> tuple[str, ...]:
        """Promote and optionally hand off matching artifacts without losing provenance."""
        with self._write() as conn:
            rows = conn.execute(
                "SELECT id, consumers_json FROM tactical_artifacts WHERE challenge_id=? AND artifact_type=?",
                (challenge_id, artifact_type),
            ).fetchall()
            for row in rows:
                consumers = json.loads(row["consumers_json"] or "[]")
                if consumer and consumer not in consumers:
                    consumers.append(consumer)
                conn.execute(
                    "UPDATE tactical_artifacts SET trust_state='promoted', consumers_json=? WHERE id=?",
                    (json.dumps(consumers, sort_keys=True), row["id"]),
                )
        return tuple(str(row["id"]) for row in rows)

    def handoff_tactical_artifacts(
        self, *, challenge_id: str, producer_contract_id: str, filenames: Iterable[str],
        consumer_contract_ids: Iterable[str],
    ) -> tuple[str, ...]:
        """Record concrete producer-to-consumer edges for snapshotted files."""
        names = {Path(str(item)).name for item in filenames}
        consumers = tuple(dict.fromkeys(str(item) for item in consumer_contract_ids if item))
        if not names or not consumers:
            return ()
        updated: list[str] = []
        with self._write() as conn:
            rows = conn.execute(
                "SELECT id, path, consumers_json FROM tactical_artifacts "
                "WHERE challenge_id=? AND contract_id=?",
                (challenge_id, producer_contract_id),
            ).fetchall()
            for row in rows:
                if Path(str(row["path"])).name not in names:
                    continue
                current = list(json.loads(row["consumers_json"] or "[]"))
                for consumer in consumers:
                    if consumer not in current:
                        current.append(consumer)
                conn.execute(
                    "UPDATE tactical_artifacts SET trust_state='promoted', consumers_json=? WHERE id=?",
                    (json.dumps(current, sort_keys=True), row["id"]),
                )
                updated.append(str(row["id"]))
        return tuple(updated)

    def list_tactical_artifacts(self, challenge_id: str) -> list[dict[str, Any]]:
        """Return persisted artifact manifests with decoded provenance edges."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM tactical_artifacts WHERE challenge_id=? ORDER BY created_at, id",
                (challenge_id,),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["content_metadata"] = json.loads(item.pop("metadata_json") or "{}")
            item["consumers"] = json.loads(item.pop("consumers_json") or "[]")
            result.append(item)
        return result

    def append_fenced_event(
        self, event: Event, *, attempt_id: str, owner: str | None, fencing_token: int | None,
        now: datetime | str | None = None,
    ) -> Event:
        """Append one worker-attributable event only under its live lease."""
        if event.attempt_id != attempt_id:
            raise StateTransitionError("fenced event attempt identity does not match its lease")
        with self._write() as conn:
            self._require_active_attempt_lease_conn(conn, attempt_id, owner, fencing_token, now=now)
            self._record_event_conn(conn, event)
        self._notify_committed_events((event,))
        return event

    def run_fenced_operation(
        self,
        *,
        attempt_id: str,
        owner: str | None,
        fencing_token: int | None,
        operation: Callable[[], _OperationResult],
        events: Callable[[_OperationResult], Iterable[Event]] | Iterable[Event] = (),
        now: datetime | str | None = None,
    ) -> _OperationResult:
        """Hold the attempt fence across an aggregate side-effect operation.

        This is intentionally a narrow coordinator primitive.  It keeps the
        SQLite write transaction (and therefore reassignment) locked from the
        successful lease check through the filesystem promotion and durable
        outbox event insert.  A stale worker never receives this capability;
        it can only write its disposable private capture.
        """
        with self._write() as conn:
            self._require_active_attempt_lease_conn(conn, attempt_id, owner, fencing_token, now=now)
            outcome = operation()
            emitted = tuple(events(outcome) if callable(events) else events)
            for event in emitted:
                if event.attempt_id != attempt_id:
                    raise StateTransitionError("fenced operation event has the wrong attempt identity")
                self._record_event_conn(conn, event)
        self._notify_committed_events(emitted)
        return outcome

    def list_events(self, *, challenge_id: str | None = None) -> list[Event]:
        query, values = "SELECT * FROM events", []
        if challenge_id is not None:
            query += " WHERE challenge_id = ?"
            values.append(challenge_id)
        query += " ORDER BY created_at, id"
        with self._connect() as conn:
            rows = conn.execute(query, values).fetchall()
        events: list[Event] = []
        for row in rows:
            if row["event_json"]:
                events.append(Event.from_dict(json.loads(row["event_json"])))
            else:  # compatibility for an older, already-created database
                events.append(Event(
                    id=row["id"], timestamp=row["created_at"], team_id="local", member="local", contest="local",
                    type=row["type"], challenge_id=row["challenge_id"], attempt_id=row["attempt_id"],
                    message=row["message"], payload=json.loads(row["payload_json"] or "{}"),
                ))
        return events

    def pending_outbox(self, *, limit: int = 100) -> list[OutboxRecord]:
        if limit < 1:
            return []
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT event_json, attempts, last_error FROM outbox WHERE published_at IS NULL ORDER BY created_at, rowid LIMIT ?",
                (limit,),
            ).fetchall()
        return [OutboxRecord(Event.from_dict(json.loads(row["event_json"])), int(row["attempts"]), row["last_error"]) for row in rows]

    def mark_outbox_published(self, event_id: str, *, now: datetime | str | None = None) -> None:
        with self._write() as conn:
            conn.execute("UPDATE outbox SET published_at=?, last_error=NULL WHERE event_id=?", (self._now(now), event_id))

    def mark_outbox_failed(self, event_id: str, error: str) -> None:
        with self._write() as conn:
            conn.execute("UPDATE outbox SET attempts=attempts+1, last_error=? WHERE event_id=? AND published_at IS NULL", (error[:1000], event_id))

    def add_flag_candidate(self, candidate: FlagCandidate) -> FlagCandidate:
        with self._write() as conn:
            self._add_candidate_conn(conn, candidate)
        return candidate

    @staticmethod
    def _add_candidate_conn(conn: sqlite3.Connection, candidate: FlagCandidate) -> None:
        conn.execute("""
            INSERT INTO flag_candidates (
              id, challenge_id, challenge_key, attempt_id, value, source, confidence, verified, verification_status,
              verification_reason, synthetic, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(challenge_id, value) DO UPDATE SET
              challenge_key=excluded.challenge_key,
              attempt_id=COALESCE(excluded.attempt_id, flag_candidates.attempt_id),
              source=excluded.source, confidence=excluded.confidence,
              verified=CASE WHEN flag_candidates.verified=1 THEN 1 ELSE excluded.verified END,
              verification_status=CASE
                WHEN flag_candidates.verification_status IN ('VERIFIED','REJECTED','REPLAY_VERIFIED')
                THEN flag_candidates.verification_status ELSE excluded.verification_status END,
              verification_reason=CASE
                WHEN flag_candidates.verification_status IN ('VERIFIED','REJECTED','REPLAY_VERIFIED')
                THEN flag_candidates.verification_reason ELSE excluded.verification_reason END,
              synthetic=excluded.synthetic
        """, _candidate_values(candidate))

    def record_candidate(
        self, candidate: FlagCandidate, event: Event, *, owner: str | None, fencing_token: int | None,
        promote_challenge_status: bool = True,
        now: datetime | str | None = None,
    ) -> FlagCandidate:
        """Persist candidate evidence and its append-only event in one commit."""
        if not candidate.attempt_id:
            raise StateTransitionError("candidate verification requires the owning attempt")
        with self._write() as conn:
            self._require_active_attempt_lease_conn(conn, candidate.attempt_id, owner, fencing_token, now=now)
            self._add_candidate_conn(conn, candidate)
            if promote_challenge_status:
                conn.execute(
                    "UPDATE challenges SET status=?, updated_at=? WHERE id=? AND status=?",
                    (ChallengeStatus.FLAG_CANDIDATE.value, self._now(now), candidate.challenge_id, ChallengeStatus.RUNNING.value),
                )
            self._record_event_conn(conn, event)
        self._notify_committed_events((event,))
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM flag_candidates WHERE challenge_id=? AND value=?",
                (candidate.challenge_id, candidate.value),
            ).fetchone()
        if row is None:  # pragma: no cover - same transaction inserted or retained it
            raise StateError("candidate commit completed without a durable row")
        return _candidate_from_row(row)

    def set_candidate_verification(
        self, candidate_id: str, *, status: str, reason: str = "", verified: bool = False,
        owner: str | None, fencing_token: int | None, now: datetime | str | None = None,
    ) -> FlagCandidate:
        status = status.upper()
        if status not in {"RAW_CANDIDATE", "CANDIDATE", "VERIFYING", "REPLAY_VERIFIED", "VERIFIED", "REJECTED", "UNAVAILABLE"}:
            raise ValueError("invalid verification status")
        with self._write() as conn:
            candidate = conn.execute("SELECT attempt_id FROM flag_candidates WHERE id=?", (candidate_id,)).fetchone()
            if candidate is None:
                raise KeyError(f"unknown flag candidate: {candidate_id}")
            if not candidate["attempt_id"]:
                raise StateTransitionError("candidate has no owning attempt lease")
            self._require_active_attempt_lease_conn(conn, str(candidate["attempt_id"]), owner, fencing_token, now=now)
            conn.execute(
                "UPDATE flag_candidates SET verification_status=?, verification_reason=?, verified=? WHERE id=?",
                (status, reason or None, int(verified), candidate_id),
            )
        row = self._candidate_by_id(candidate_id)
        assert row is not None
        return row

    def solve_verified(
        self, *, candidate_id: str, flag: str, event: Event, synthetic: bool = False,
        owner: str | None, fencing_token: int | None, now: datetime | str | None = None,
    ) -> Challenge:
        """Atomically persist verified evidence, immutable SOLVED, and outbox event."""
        with self._write() as conn:
            candidate = conn.execute("SELECT challenge_id, value, attempt_id FROM flag_candidates WHERE id=?", (candidate_id,)).fetchone()
            if candidate is None:
                raise KeyError(f"unknown flag candidate: {candidate_id}")
            if candidate["value"] != flag:
                raise StateTransitionError("verified flag must equal the recorded candidate")
            if not candidate["attempt_id"]:
                raise StateTransitionError("candidate has no owning attempt lease")
            self._require_active_attempt_lease_conn(conn, str(candidate["attempt_id"]), owner, fencing_token, now=now)
            challenge = conn.execute("SELECT status, flag FROM challenges WHERE id=?", (candidate["challenge_id"],)).fetchone()
            if challenge is None:
                raise KeyError("candidate references an unknown challenge")
            if challenge["status"] == ChallengeStatus.SOLVED.value:
                if challenge["flag"] != flag:
                    raise StateTransitionError("SOLVED is immutable")
            else:
                conn.execute(
                    "UPDATE challenges SET status=?, flag=?, synthetic=?, updated_at=? WHERE id=?",
                    (ChallengeStatus.SOLVED.value, flag, int(synthetic), self._now(now), candidate["challenge_id"]),
                )
            conn.execute(
                "UPDATE flag_candidates SET verified=1, verification_status='VERIFIED', verification_reason='verification succeeded' WHERE id=?",
                (candidate_id,),
            )
            if self._table_exists(conn, "challenge_sessions"):
                conn.execute(
                    "UPDATE challenge_sessions SET status=?, updated_at=? WHERE challenge_id=?",
                    (SessionStatus.COMPLETED.value, self._now(now), candidate["challenge_id"]),
                )
            self._record_event_conn(conn, event)
        self._notify_committed_events((event,))
        return self.get_challenge(str(candidate["challenge_id"]))  # type: ignore[return-value]

    def solve_replay_approved(
        self, *, candidate_id: str, flag: str, event: Event, leader_attempt_id: str,
        now: datetime | str | None = None,
    ) -> Challenge:
        """Commit SOLVED only after replay verification and a completed Sol leader decision."""
        with self._write() as conn:
            candidate = conn.execute(
                "SELECT challenge_id, value, verification_status FROM flag_candidates WHERE id=?",
                (candidate_id,),
            ).fetchone()
            leader = conn.execute(
                "SELECT challenge_id, role, profile, status FROM attempts WHERE id=?",
                (leader_attempt_id,),
            ).fetchone()
            if candidate is None or leader is None:
                raise KeyError("candidate or Sol leader attempt is missing")
            if candidate["value"] != flag or candidate["verification_status"] != "REPLAY_VERIFIED":
                raise StateTransitionError("Sol may approve only the exact replay-verified candidate")
            if (leader["challenge_id"] != candidate["challenge_id"] or
                    leader["role"] != "session_leader" or leader["profile"] != "session_leader" or
                    leader["status"] != AttemptStatus.SUCCEEDED.value):
                raise StateTransitionError("approval requires a successful persistent Sol leader attempt")
            conn.execute(
                "UPDATE challenges SET status=?, flag=?, synthetic=0, updated_at=? WHERE id=? AND status<>?",
                (ChallengeStatus.SOLVED.value, flag, self._now(now), candidate["challenge_id"], ChallengeStatus.SOLVED.value),
            )
            conn.execute(
                "UPDATE flag_candidates SET verified=1, verification_status='VERIFIED', "
                "verification_reason='sandbox replay verified and Sol approved' WHERE id=?",
                (candidate_id,),
            )
            conn.execute(
                "UPDATE challenge_sessions SET status=?, updated_at=? WHERE challenge_id=?",
                (SessionStatus.COMPLETED.value, self._now(now), candidate["challenge_id"]),
            )
            self._record_event_conn(conn, event)
        self._notify_committed_events((event,))
        return self.get_challenge(str(candidate["challenge_id"]))  # type: ignore[return-value]

    def _candidate_by_id(self, candidate_id: str) -> FlagCandidate | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM flag_candidates WHERE id=?", (candidate_id,)).fetchone()
        return _candidate_from_row(row) if row else None

    def list_flag_candidates(
        self, challenge_id: str, *, attempt_id: str | None = None,
        verification_statuses: Iterable[str] | None = None,
    ) -> list[FlagCandidate]:
        clauses = ["challenge_id = ?"]
        values: list[Any] = [challenge_id]
        if attempt_id is not None:
            clauses.append("attempt_id = ?")
            values.append(attempt_id)
        statuses = tuple(status.upper() for status in verification_statuses or ())
        if statuses:
            clauses.append("verification_status IN (" + ",".join("?" for _ in statuses) + ")")
            values.extend(statuses)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM flag_candidates WHERE " + " AND ".join(clauses) + " ORDER BY created_at, id", values,
            ).fetchall()
        return [_candidate_from_row(row) for row in rows]

    # --- model rate-limit/unavailability state ---------------------------------------

    def model_in_cooldown(
        self,
        model: str,
        *,
        selection_key: str | None = None,
        now: datetime | str | None = None,
    ) -> bool:
        """Return whether a selection (or explicit model-global key) is cooling down.

        The original model-only API remains model-global: callers that do not
        provide ``selection_key`` read ``model:<model>``.  Selection-aware
        callers also honour a model-global record, preserving the ability for
        policy to deliberately stop every profile of one raw model.
        """
        if not model:
            raise ValueError("model is required")
        keys = (selection_key, f"model:{model}") if selection_key else (f"model:{model}",)
        placeholders = ",".join("?" for _ in keys)
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT 1 FROM model_cooldowns WHERE selection_key IN ({placeholders}) "
                "AND expires_at > ? LIMIT 1",
                (*keys, self._now(now)),
            ).fetchone()
        return row is not None

    def set_model_cooldown(
        self,
        model: str,
        *,
        reason: str,
        seconds: float,
        selection_key: str | None = None,
        now: datetime | str | None = None,
    ) -> None:
        if not model or seconds <= 0:
            raise ValueError("model and positive cooldown seconds are required")
        if selection_key is not None and not selection_key:
            raise ValueError("selection_key must be non-empty when set")
        from datetime import timedelta
        timestamp = ensure_utc(now if now is not None else self._clock())
        key = selection_key or f"model:{model}"
        with self._write() as conn:
            self._set_model_cooldown_conn(
                conn,
                model=model,
                selection_key=key,
                reason=reason,
                timestamp=timestamp,
                seconds=seconds,
            )

    def record_model_cooldown(
        self,
        *,
        model: str,
        selection_key: str,
        reason: str,
        seconds: float,
        event: Event,
        owner: str | None,
        fencing_token: int | None,
        now: datetime | str | None = None,
    ) -> None:
        """Fence cooldown state and its visible lifecycle event in one commit."""
        if not model or not selection_key or seconds <= 0:
            raise ValueError("model, selection_key, and positive cooldown seconds are required")
        if not event.attempt_id:
            raise StateTransitionError("model cooldown event requires the owning attempt")
        timestamp = ensure_utc(now if now is not None else self._clock())
        with self._write() as conn:
            self._require_active_attempt_lease_conn(
                conn, event.attempt_id, owner, fencing_token, now=timestamp,
            )
            self._set_model_cooldown_conn(
                conn,
                model=model,
                selection_key=selection_key,
                reason=reason,
                timestamp=timestamp,
                seconds=seconds,
            )
            self._record_event_conn(conn, event)

    @staticmethod
    def _set_model_cooldown_conn(
        conn: sqlite3.Connection,
        *,
        model: str,
        selection_key: str,
        reason: str,
        timestamp: datetime,
        seconds: float,
    ) -> None:
        from datetime import timedelta

        conn.execute(
            "INSERT INTO model_cooldowns(selection_key, model, reason, expires_at, updated_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(selection_key) DO UPDATE SET model=excluded.model, reason=excluded.reason, expires_at=excluded.expires_at, updated_at=excluded.updated_at",
            (selection_key, model, reason, timestamp_text(timestamp + timedelta(seconds=seconds)), timestamp_text(timestamp)),
        )

    def quota_warning_in_cooldown(self, *, now: datetime | str | None = None) -> bool:
        """Whether a quota-class cooldown should visibly suppress new work."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM model_cooldowns WHERE expires_at > ? "
                "AND lower(reason) LIKE '%quota%' LIMIT 1",
                (self._now(now),),
            ).fetchone()
        return row is not None


def allowed_transitions(status: ChallengeStatus | str) -> frozenset[ChallengeStatus]:
    return _TRANSITIONS[ChallengeStatus(_status_text(status))]


def _status_text(status: ChallengeStatus | str) -> str:
    return status.value if isinstance(status, ChallengeStatus) else str(status).upper()


def _challenge_from_row(row: sqlite3.Row) -> Challenge:
    return Challenge(
        id=row["id"], contest=row["contest"], category=row["category"], name=row["name"], slug=row["slug"],
        challenge_key=row["challenge_key"],
        score=row["score"], remote=row["remote"], description=row["description"], hint=row["hint"],
        flag_format=row["flag_format"], flag_pattern=row["flag_pattern"], status=ChallengeStatus(row["status"]),
        assignee=row["assignee"], flag=row["flag"], synthetic=bool(row["synthetic"]),
        created_at=row["created_at"], updated_at=row["updated_at"],
    )


def _attempt_values(attempt: Attempt) -> tuple[Any, ...]:
    status = attempt.status.value if isinstance(attempt.status, AttemptStatus) else str(attempt.status)
    return (
        attempt.id, attempt.challenge_id, attempt.profile, attempt.role, attempt.backend, attempt.model,
        attempt.model_profile, attempt.reasoning_effort,
        attempt.pid, attempt.container_name, attempt.session_id, attempt.resume_id, attempt.workdir, status,
        timestamp_text(attempt.started_at) if attempt.started_at else None,
        timestamp_text(attempt.ended_at) if attempt.ended_at else None, attempt.token_total,
        int(attempt.synthetic), attempt.cleanup_status, attempt.cleanup_message,
        attempt.lease_owner, attempt.fencing_token,
    )


def _json_value(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _challenge_session_values(session: ChallengeSession) -> tuple[Any, ...]:
    status = session.status.value if isinstance(session.status, SessionStatus) else str(session.status).upper()
    return (
        session.id, session.challenge_id, session.leader_model, session.leader_profile,
        session.reasoning_effort, status, session.leader_session_id, session.leader_resume_id,
        _json_value(dict(session.execution_contract)), _json_value(dict(session.summary_state)),
        session.generation, timestamp_text(session.created_at), timestamp_text(session.updated_at),
    )


def _challenge_session_from_row(row: sqlite3.Row) -> ChallengeSession:
    return ChallengeSession(
        id=row["id"], challenge_id=row["challenge_id"], leader_model=row["leader_model"],
        leader_profile=row["leader_profile"], reasoning_effort=row["reasoning_effort"],
        status=row["status"], leader_session_id=row["leader_session_id"],
        leader_resume_id=row["leader_resume_id"],
        execution_contract=json.loads(row["execution_contract_json"]),
        summary_state=json.loads(row["summary_state_json"]), generation=row["generation"],
        created_at=row["created_at"], updated_at=row["updated_at"],
    )


def _contract_task_values(task: ContractTask) -> tuple[Any, ...]:
    status = task.status.value if isinstance(task.status, ContractTaskStatus) else str(task.status).upper()
    return (
        task.id, task.session_id, task.challenge_id, task.branch, task.role, task.objective,
        status, task.backend, task.model_profile, task.reasoning_effort, task.prompt_family,
        task.timeout_sec, task.tool_strategy, task.priority,
        _json_value(task.success_criteria), _json_value(task.deliverables),
        task.failure_handoff, _json_value(task.depends_on), task.assigned_attempt_id,
        task.result_summary, _json_value(task.evidence_ids), timestamp_text(task.created_at),
        timestamp_text(task.updated_at),
    )


def _contract_task_from_row(row: sqlite3.Row) -> ContractTask:
    return ContractTask(
        id=row["id"], session_id=row["session_id"], challenge_id=row["challenge_id"],
        branch=row["branch"], role=row["role"], objective=row["objective"], status=row["status"],
        backend=row["backend"], model_profile=row["model_profile"],
        reasoning_effort=row["reasoning_effort"], prompt_family=row["prompt_family"],
        timeout_sec=row["timeout_sec"], tool_strategy=row["tool_strategy"],
        priority=row["priority"],
        success_criteria=tuple(json.loads(row["success_criteria_json"])),
        deliverables=tuple(json.loads(row["deliverables_json"])),
        failure_handoff=row["failure_handoff"],
        depends_on=tuple(json.loads(row["depends_on_json"])),
        assigned_attempt_id=row["assigned_attempt_id"], result_summary=row["result_summary"],
        evidence_ids=tuple(json.loads(row["evidence_ids_json"])),
        created_at=row["created_at"], updated_at=row["updated_at"],
    )


def _attempt_from_row(row: sqlite3.Row) -> Attempt:
    try:
        status: AttemptStatus | str = AttemptStatus(row["status"])
    except ValueError:
        status = row["status"]
    return Attempt(
        id=row["id"], challenge_id=row["challenge_id"], profile=row["profile"], role=row["role"],
        backend=row["backend"], model=row["model"], model_profile=row["model_profile"],
        reasoning_effort=row["reasoning_effort"], pid=row["pid"], container_name=row["container_name"],
        session_id=row["session_id"], resume_id=row["resume_id"],
        workdir=row["workdir"], status=status, started_at=row["started_at"], ended_at=row["ended_at"],
        token_total=row["token_total"], synthetic=bool(row["synthetic"]),
        cleanup_status=row["cleanup_status"], cleanup_message=row["cleanup_message"],
        lease_owner=row["lease_owner"], fencing_token=row["fencing_token"],
    )


def _candidate_values(candidate: FlagCandidate) -> tuple[Any, ...]:
    return (
        candidate.id, candidate.challenge_id, candidate.challenge_key, candidate.attempt_id, candidate.value, candidate.source,
        candidate.confidence, int(candidate.verified), candidate.verification_status.upper(),
        candidate.verification_reason, int(candidate.synthetic), timestamp_text(candidate.created_at),
    )


def _candidate_from_row(row: sqlite3.Row) -> FlagCandidate:
    return FlagCandidate(
        id=row["id"], challenge_id=row["challenge_id"], challenge_key=row["challenge_key"], attempt_id=row["attempt_id"], value=row["value"],
        source=row["source"], confidence=row["confidence"], verified=bool(row["verified"]),
        verification_status=row["verification_status"] or "CANDIDATE", verification_reason=row["verification_reason"],
        synthetic=bool(row["synthetic"]), created_at=row["created_at"],
    )
