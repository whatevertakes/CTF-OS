"""Local operator dashboards.

The deterministic plain renderer remains the non-interactive fallback.  The
Textual dashboard below consumes the same challenge-owned projection and uses
the local challenge id as its stable DataTable row key.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timezone
from threading import get_ident
from typing import Iterable

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import DataTable, Footer, Header, Static

from .config import AppConfig
from .local_event_bus import EventLogDiagnostic
from .local_state import LocalState
from .merged_team_state import MergedTeamState
from .models import Attempt, AttemptStatus, Challenge, ChallengeStatus, Event, FlagCandidate
from .team_sync import TeamSync


_ACTIVE_ATTEMPT_STATUSES = frozenset({AttemptStatus.QUEUED, AttemptStatus.RUNNING})
_OPERATOR_EVENT_TYPES = frozenset({
    "STALE_RECOVERY", "ORPHAN_CLEANUP", "SANDBOX_CLEANUP", "SANDBOX_CLEANUP_FAILED",
})


@dataclass(frozen=True, slots=True)
class ChallengeView:
    challenge_id: str
    challenge_key: str
    name: str
    category: str
    score: int | None
    assignee: str | None
    status: str
    active_attempts: int
    verified_flag: str | None
    latest_candidate: str | None
    candidate_source_attempt: str | None
    solved_by_member: str | None

    @property
    def full_flag(self) -> str | None:
        return self.verified_flag or self.latest_candidate

    def flag_text(self, *, compact: bool = False, width: int = 36) -> str:
        if self.verified_flag:
            value = self.verified_flag
        elif self.latest_candidate:
            value = f"? {self.latest_candidate}"
        else:
            return "-"
        if compact and len(value) > width:
            return value[: max(1, width - 1)] + "…"
        return value


def challenge_view(
    state: LocalState,
    challenge_id: str,
    *,
    team_state: MergedTeamState | None = None,
) -> ChallengeView | None:
    """Project one challenge and only its owned flag candidates."""
    challenge = state.get_challenge(challenge_id)
    if challenge is None:
        return None
    team = (team_state or MergedTeamState()).get(challenge.challenge_key)
    attempts = state.list_attempts(challenge.id)
    candidates = state.list_flag_candidates(challenge.id)
    candidate = _primary_candidate(candidates)
    verified = challenge.flag or (team.solved_flag if team else None)
    latest = None if verified else ((candidate.value if candidate else None) or (team.candidate_flag if team else None))
    return ChallengeView(
        challenge_id=challenge.id,
        challenge_key=challenge.challenge_key,
        name=challenge.name,
        category=challenge.category,
        score=challenge.score,
        assignee=challenge.assignee,
        status=_display_status(challenge, team),
        active_attempts=sum(_attempt_is_active(attempt) for attempt in attempts),
        verified_flag=verified,
        latest_candidate=latest,
        candidate_source_attempt=candidate.attempt_id if candidate else None,
        solved_by_member=getattr(team, "solved_by_member", None) if team else None,
    )


class CTFOSDashboard(App[None]):
    """Reactive dashboard whose authoritative mapping is challenge id -> row."""

    BINDINGS = [Binding("c", "copy_flag", "Copy full flag")]
    _COLUMNS = (
        ("problem", "problem"), ("category", "category"), ("score", "score"),
        ("assignee", "assignee"), ("status", "status"),
        ("active workers", "workers"), ("flag", "flag"),
    )

    def __init__(self, config: AppConfig, state: LocalState, *, team_state: MergedTeamState | None = None) -> None:
        super().__init__()
        self.config = config
        self.local_state = state
        self.team_state = team_state or MergedTeamState()
        self._views: dict[str, ChallengeView] = {}
        self._ui_thread_id: int | None = None
        self._known_local_events: set[str] = set()
        self._known_team_events: set[str] = set()
        self._unsubscribe_local_events = None

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield DataTable(id="challenges", cursor_type="row")
            yield Static("Select a challenge to see its complete flag.", id="challenge-detail", markup=False)
            yield Static("", id="event-log", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self._ui_thread_id = get_ident()
        table = self.query_one("#challenges", DataTable)
        for label, key in self._COLUMNS:
            table.add_column(label, key=key)
        for challenge in self.local_state.list_challenges():
            self.refresh_challenge(challenge.id)
        self._known_local_events = {event.id for event in self.local_state.list_events()}
        self._known_team_events = {
            event.id
            for item in self.team_state.challenges.values()
            for event in item.events
        }
        self._unsubscribe_local_events = self.local_state.subscribe_events(self._on_committed_event)
        self.set_interval(max(.25, self.config.poll_interval_sec), self._poll_changes)

    def on_unmount(self) -> None:
        if self._unsubscribe_local_events is not None:
            self._unsubscribe_local_events()
            self._unsubscribe_local_events = None

    def _on_committed_event(self, event: Event) -> None:
        if event.type not in {"FLAG_CANDIDATE", "VERIFYING", "SOLVED"}:
            return
        challenge_id = event.challenge_id
        if challenge_id and self.local_state.get_challenge(challenge_id) is None:
            challenge_id = None
        if not challenge_id and event.challenge_key:
            challenge_id = next(
                (item.id for item in self.local_state.list_challenges() if item.challenge_key == event.challenge_key),
                None,
            )
        if challenge_id:
            self._known_local_events.add(event.id)
            self.notify_challenge_changed(challenge_id, event)

    def refresh_challenge(self, challenge_id: str, event: Event | None = None) -> None:
        """Update exactly one keyed row; safe to schedule via notify below."""
        view = challenge_view(self.local_state, challenge_id, team_state=self.team_state)
        if view is None:
            return
        table = self.query_one("#challenges", DataTable)
        values = self._row_values(view)
        if challenge_id not in table.rows:
            table.add_row(*values, key=challenge_id)
        else:
            for (_, column_key), value in zip(self._COLUMNS, values, strict=True):
                table.update_cell(challenge_id, column_key, value)
        self._views[challenge_id] = view
        if event is not None and event.type in {"FLAG_CANDIDATE", "VERIFYING", "SOLVED"}:
            self._append_flag_event(event, view)
        self._refresh_detail_for_cursor()

    def notify_challenge_changed(self, challenge_id: str, event: Event | None = None) -> None:
        """Entry point for subprocess readers, worker threads, and async tasks."""
        if self._ui_thread_id == get_ident():
            self.refresh_challenge(challenge_id, event)
        else:
            self.call_from_thread(self.refresh_challenge, challenge_id, event)

    def on_data_table_row_highlighted(self, _: DataTable.RowHighlighted) -> None:
        self._refresh_detail_for_cursor()

    def selected_view(self) -> ChallengeView | None:
        table = self.query_one("#challenges", DataTable)
        if table.row_count == 0:
            return None
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        return self._views.get(str(row_key.value))

    def action_copy_flag(self) -> None:
        view = self.selected_view()
        if view and view.full_flag:
            self.copy_to_clipboard(view.full_flag)
            self.notify(f"Copied flag for {view.category}/{view.name}")

    def _row_values(self, view: ChallengeView) -> tuple[str, ...]:
        return (
            view.name, view.category, str(view.score if view.score is not None else "-"),
            view.assignee or "-", view.status, str(view.active_attempts),
            view.flag_text(compact=True),
        )

    def _refresh_detail_for_cursor(self) -> None:
        view = self.selected_view()
        if view is None:
            return
        flag = view.full_flag or "-"
        source = view.candidate_source_attempt or view.solved_by_member or "-"
        self.query_one("#challenge-detail", Static).update(
            f"{view.category}/{view.name}\nchallenge_id={view.challenge_id}\n"
            f"challenge_key={view.challenge_key}\nstatus={view.status}\n"
            f"full_flag={flag}\nflag_source={source}"
        )

    def _append_flag_event(self, event: Event, view: ChallengeView) -> None:
        flag = event.payload.get("flag") if isinstance(event.payload, dict) else None
        attempt = f"[{event.attempt_id}]" if event.attempt_id else ""
        locality = "LOCAL" if event.member == self.config.member_name else f"TEAM][{event.member}"
        prefix = f"[{locality}][{view.category}/{view.name}]{attempt}"
        log = self.query_one("#event-log", Static)
        prior = str(log.renderable or "")
        log.update((prior + "\n" if prior else "") + f"{prefix} {event.type}: {flag or event.message or '-'}")

    def _poll_changes(self) -> None:
        """Fallback refresh for changes not delivered by the in-process bus."""
        local_events = self.local_state.list_events()
        changed = [event for event in local_events if event.id not in self._known_local_events]
        self._known_local_events.update(event.id for event in changed)

        sync = TeamSync(self.config.sync_root, team_id=self.config.team_id, member=self.config.member_name)
        team_events = sync.merge_report().events
        new_team = [event for event in team_events if event.id not in self._known_team_events]
        self._known_team_events.update(event.id for event in new_team)
        if new_team:
            self.team_state = MergedTeamState.from_events(team_events)

        local_by_key = {item.challenge_key: item.id for item in self.local_state.list_challenges()}
        for event in (*changed, *new_team):
            challenge_id = event.challenge_id if self.local_state.get_challenge(event.challenge_id or "") else None
            challenge_id = challenge_id or local_by_key.get(event.challenge_key or "")
            if challenge_id:
                self.refresh_challenge(challenge_id, event)


def render_tui(
    config: AppConfig,
    state: LocalState | None,
    *,
    team_state: MergedTeamState | None = None,
    show_team: bool = False,
    sync_diagnostics: Iterable[EventLogDiagnostic] = (),
) -> str:
    """Render a side-effect-free dashboard suitable for TTYs and tests.

    The caller owns polling and screen refresh.  This function only reads
    SQLite/TeamSync-derived values, making it safe for ``tui --readonly`` and
    preventing the display path from ever participating in scheduling.
    """
    team_state = team_state or MergedTeamState()
    challenges = state.list_challenges() if state is not None else []
    events = state.list_events() if state is not None else []
    events_by_challenge: dict[str, list[Event]] = {}
    events_by_attempt: dict[str, list[Event]] = {}
    for event in events:
        if event.challenge_id:
            events_by_challenge.setdefault(event.challenge_id, []).append(event)
        if event.attempt_id:
            events_by_attempt.setdefault(event.attempt_id, []).append(event)

    rows: list[tuple[str, ...]] = []
    attempt_details: list[str] = []
    all_attempts: list[Attempt] = []
    for challenge in challenges:
        assert state is not None
        attempts = state.list_attempts(challenge.id)
        all_attempts.extend(attempts)
        active = sum(_attempt_is_active(attempt) for attempt in attempts)
        latest_attempt = attempts[-1] if attempts else None
        candidates = state.list_flag_candidates(challenge.id)
        team = team_state.get(challenge.challenge_key) or team_state.get(challenge.id)
        status = _display_status(challenge, team)
        flag_text = _flag_text(challenge, candidates, team)
        model = _model_text(latest_attempt)
        reason = _latest_message(
            events_by_challenge.get(challenge.id, ()),
            {"PAUSED", "STUCK", "HINTING", "SUPERVISOR_UNAVAILABLE", "SUPERVISOR_HINT"},
        )
        team_members = ",".join(team.running_members) if show_team and team else ""
        rows.append((
            challenge.name,
            challenge.category,
            str(challenge.score or "-"),
            challenge.assignee or "-",
            status,
            str(active),
            model,
            flag_text,
            reason,
            team_members,
        ))
        for attempt in attempts:
            attempt_details.append(_attempt_detail(
                challenge, attempt,
                events_by_attempt.get(attempt.id, ()),
                candidates,
            ))

    if show_team:
        local_ids = {identity for challenge in challenges for identity in (challenge.id, challenge.challenge_key)}
        for item in sorted(team_state.challenges.values(), key=lambda value: (value.contest, value.category or "", value.name or "")):
            if item.key in local_ids:
                continue
            flag_text = (
                f"TEAM_SOLVED: {item.solved_flag}" if item.solved_flag else
                f"TEAM_CANDIDATE: {item.candidate_flag}" if item.candidate_flag else "-"
            )
            status = "DUPLICATE_RUNNING" if item.duplicate_running else f"TEAM_{item.status}"
            # Team-only work has no local Attempt rows.  Its worker count is
            # the merged member reduction, never a placeholder zero.
            rows.append((
                item.name or item.key,
                item.category or "-",
                "-",
                "-",
                status,
                str(len(item.running_members)),
                "-",
                flag_text,
                "-",
                ",".join(item.running_members),
            ))

    headers = ("problem", "category", "score", "assignee", "status", "active workers", "model", "flag", "reason / supervisor hint", "team running")
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    line = "+".join("-" * (width + 2) for width in widths)

    def format_row(values: tuple[str, ...]) -> str:
        return "|".join(f" {value:<{widths[index]}} " for index, value in enumerate(values))

    title = f"CTF-OS Local Node | {config.contest_name} | {config.member_display_name} | {config.team_id}"
    body = [title, line, format_row(headers), line]
    body.extend(format_row(row) for row in rows)
    body.append(line)
    body.extend(_node_summary(config, state, all_attempts, events))
    if attempt_details:
        body.append("attempt details:")
        body.extend(attempt_details)
    if team_state.duplicate_warnings:
        names = ", ".join(item.name or item.key for item in team_state.duplicate_warnings)
        body.append(f"WARNING duplicate RUNNING claims: {names}")
    for event in events:
        if event.type in _OPERATOR_EVENT_TYPES:
            body.append(f"OPERATOR {event.type}: {event.message or '-'}")
        if event.type in {"FLAG_CANDIDATE", "VERIFYING", "SOLVED"} and event.challenge_id:
            label = f"{event.category or '-'}/{event.challenge or event.challenge_id}"
            attempt = f"[{event.attempt_id}]" if event.attempt_id else ""
            flag = event.payload.get("flag") if isinstance(event.payload, dict) else None
            body.append(f"[LOCAL][{label}]{attempt} {event.type}: {flag or event.message or '-'}")
    for diagnostic in sync_diagnostics:
        body.append(f"SYNC DIAGNOSTIC {diagnostic.kind}: {diagnostic.message}")
    return "\n".join(body)


def _display_status(challenge: Challenge, team) -> str:
    if challenge.synthetic:
        return "SYNTHETIC_" + challenge.status.value
    if challenge.status is ChallengeStatus.SOLVED:
        return "SOLVED"
    if team and team.status == "SOLVED":
        return "TEAM_SOLVED"
    if team and team.duplicate_running:
        return "DUPLICATE_RUNNING"
    if challenge.status is ChallengeStatus.RUNNING:
        return "LOCAL_RUNNING"
    if challenge.status is ChallengeStatus.STUCK:
        return "LOCAL_STUCK"
    if challenge.status is ChallengeStatus.HINTING:
        return "LOCAL_HINTING"
    if challenge.status is ChallengeStatus.PAUSED:
        return "PAUSED"
    if team and team.running_members:
        return "TEAM_RUNNING"
    return challenge.status.value


def _flag_text(challenge: Challenge, candidates: list[FlagCandidate], team) -> str:
    if challenge.synthetic:
        return f"SYNTHETIC SOLVED: {challenge.flag}" if challenge.flag else "SYNTHETIC"
    if challenge.flag:
        return f"SOLVED: {challenge.flag}"
    candidate = _primary_candidate(candidates)
    if candidate:
        return f"? {candidate.value}"
    if team and team.solved_flag:
        return f"TEAM_SOLVED: {team.solved_flag}"
    if team and team.candidate_flag:
        return f"TEAM_CANDIDATE: {team.candidate_flag}"
    return "-"


def _primary_candidate(candidates: Iterable[FlagCandidate]) -> FlagCandidate | None:
    active = [item for item in candidates if item.verification_status not in {"REJECTED", "UNAVAILABLE"}]
    if not active:
        return None
    return max(active, key=lambda item: (
        item.verified,
        item.verification_status == "VERIFYING",
        item.confidence if item.confidence is not None else -1,
        item.created_at,
    ))


def _attempt_detail(challenge: Challenge, attempt: Attempt, events: Iterable[Event], candidates: list[FlagCandidate]) -> str:
    history = tuple(events)
    seed = _latest_payload(history, "WORKER_STARTED", "strategy_seed") or "-"
    finding = _latest_message(history, {"FINDING"})
    failure = _latest_message(history, {"FAIL", "FAILED"})
    candidate = next((item.value for item in reversed(candidates) if item.attempt_id == attempt.id), "-")
    supervisor_hint = _latest_message(history, {"SUPERVISOR_HINT", "SUPERVISOR_UNAVAILABLE", "HINTING", "STUCK", "PAUSED"})
    container = "-" if not attempt.container_name else f"{_attempt_status(attempt)}:{attempt.container_name}"
    model = _model_text(attempt, compact=True)
    return (
        f"attempt {attempt.id}: contest={challenge.contest} challenge={challenge.category}/{challenge.name} "
        f"challenge_id={challenge.id} challenge_key={challenge.challenge_key} status={_attempt_status(attempt)} profile={attempt.profile} role={attempt.role} "
        f"strategy_seed={seed} latest_finding={finding} latest_fail={failure} flag_candidate={candidate} "
        f"supervisor_hint={supervisor_hint} container={container} cleanup={attempt.cleanup_status or '-'} "
        f"model={model} runtime={_runtime_text(attempt)}"
    )


def _node_summary(config: AppConfig, state: LocalState | None, attempts: Iterable[Attempt], events: Iterable[Event]) -> list[str]:
    attempts = tuple(attempts)
    codex_active = sum(_attempt_is_active(attempt) and attempt.backend == "codex_cli" for attempt in attempts)
    sandbox_active = sum(_attempt_is_active(attempt) and bool(attempt.container_name) for attempt in attempts)
    warning = _cooldown_warning(state, events)
    return [
        f"local Codex active/max: {codex_active}/{config.max_workers_total} | sandbox active/max: {sandbox_active}/{config.sandbox_max_containers}",
        warning,
    ]


def _cooldown_warning(state: LocalState | None, events: Iterable[Event]) -> str:
    if state is not None and state.quota_warning_in_cooldown():
        return "quota/cooldown warning: quota cooldown active; new local workers are suppressed"
    history = tuple(events)
    unavailable = _latest_message(history, {"MODEL_UNAVAILABLE"})
    if unavailable != "-":
        return f"all models cooling: {unavailable}"
    cooldown = _latest_message(history, {"MODEL_COOLDOWN"})
    if cooldown != "-":
        return f"quota/cooldown warning: {cooldown}"
    return "quota/cooldown warning: none"


def _attempt_is_active(attempt: Attempt) -> bool:
    try:
        return AttemptStatus(str(attempt.status)) in _ACTIVE_ATTEMPT_STATUSES
    except ValueError:
        return False


def _attempt_status(attempt: Attempt) -> str:
    return attempt.status.value if isinstance(attempt.status, AttemptStatus) else str(attempt.status)


def _model_text(attempt: Attempt | None, *, compact: bool = False) -> str:
    if attempt is None or not attempt.model:
        return "-"
    profile = attempt.model_profile or "configured"
    effort = attempt.reasoning_effort or "-"
    return f"{profile}/{attempt.model}/{effort}" if compact else f"{attempt.model} ({profile}/{effort})"


def _runtime_text(attempt: Attempt) -> str:
    if attempt.started_at is None:
        return "not-started"
    if attempt.ended_at is None:
        return "active-since=" + attempt.started_at.astimezone(timezone.utc).isoformat(timespec="seconds")
    seconds = max(0.0, (attempt.ended_at - attempt.started_at).total_seconds())
    return f"{seconds:.1f}s"


def _latest_message(events: Iterable[Event], types: set[str]) -> str:
    for event in reversed(tuple(events)):
        if event.type in types:
            return str(event.payload.get("content") or event.message or "-")
    return "-"


def _latest_payload(events: Iterable[Event], event_type: str, key: str) -> str | None:
    for event in reversed(tuple(events)):
        if event.type == event_type and event.payload.get(key) is not None:
            return str(event.payload[key])
    return None
