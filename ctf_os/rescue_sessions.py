"""Durable persistent sessions owned by one exact Claude rescue."""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
import fcntl
import hashlib
import json
from pathlib import Path
import re
import secrets
import time
from typing import Any

from .rescue import RescueError, canonical_json
from .rescue_backend import artifact_snapshot, record_telemetry, sha256_file
from .rescue_session_backend import DockerSessionBackend, SESSION_KINDS
from .sandbox.runtime import firewall_counters, protocol_network_observation
from .workspace import append_jsonl_fsync, atomic_json, atomic_text, read_jsonl_strict, utc_now


SESSION_EVENTS = frozenset({
    "SESSION_OPENED", "SESSION_INPUT_SENT", "SESSION_OUTPUT_OBSERVED",
    "SESSION_EXITED", "SESSION_CLOSED", "SESSION_ERROR",
})
SESSION_STATES = frozenset({"OPENING", "RUNNING", "EXITED", "CLOSED", "STALE", "ERROR"})
MAX_READ_BYTES = 256 * 1024
MAX_SESSION_LEDGER_BYTES = 8 * 1024 * 1024
MAX_SESSION_TRANSCRIPT_BYTES = 4 * 1024 * 1024
MAX_PERSISTENT_SESSIONS = 64
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


class RescueSessionManager:
    def __init__(
        self, run: Path, rescue_root: Path, metadata: Mapping[str, Any],
        packet: Mapping[str, Any], *, docker: str = "docker",
    ) -> None:
        self.run = run.resolve(strict=False)
        self.root = rescue_root.resolve(strict=False)
        self.metadata = dict(metadata)
        self.packet = dict(packet)
        self.docker = docker
        self.backend = DockerSessionBackend(self.root, self.metadata, docker=docker)
        self.sessions_root = self.root / "sessions"
        self.sessions_root.mkdir(parents=True, exist_ok=True)

    def list(self) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        for directory in sorted(self.sessions_root.iterdir()):
            if directory.is_symlink() or not directory.is_dir():
                continue
            try:
                rows.append(self.status(directory.name, record_exit=False))
            except RescueError as exc:
                rows.append({"session_id": directory.name, "status": "ERROR", "error": str(exc)})
        return {
            **self._identity(), "sessions": rows[-100:], "count": len(rows),
            "truncated": len(rows) > 100,
        }

    def open(
        self, *, kind: str, name: str, argv: Sequence[str] = (),
        target_index: int | None = None,
    ) -> dict[str, Any]:
        normalized_kind = str(kind).casefold()
        if normalized_kind not in SESSION_KINDS or not _NAME.fullmatch(name):
            raise RescueError("session kind or name is invalid")
        existing = self.list()["sessions"]
        if sum(row.get("status") not in {"CLOSED", "STALE"} for row in existing) >= MAX_PERSISTENT_SESSIONS:
            raise RescueError("persistent session limit is 64")
        session_id = "session-" + secrets.token_hex(8)
        directory = self.sessions_root / session_id
        directory.mkdir(mode=0o700)
        (directory / "control").mkdir(mode=0o700)
        for filename in ("transcript.jsonl", "stdout.bin", "stderr.bin"):
            (directory / filename).touch(mode=0o600)
        counters = self._network_counters()
        state: dict[str, Any] = {
            "schema_version": 1, **self._identity(), "session_id": session_id,
            "session_kind": normalized_kind, "name": name, "status": "OPENING",
            "argv": list(argv), "target_index": target_index,
            "network_counters": counters, "cursor_base": 0,
            "opened_at": utc_now(), "updated_at": utc_now(),
        }
        atomic_json(directory / "SESSION_STATE.json", state)
        try:
            if normalized_kind == "tcp":
                targets = self.metadata.get("authorized_targets")
                if not isinstance(targets, list) or not isinstance(target_index, int) or isinstance(target_index, bool) or not 0 <= target_index < len(targets):
                    raise RescueError("TCP session requires a valid declared target index")
                target = targets[target_index]
                if not isinstance(target, Mapping):
                    raise RescueError("TCP session target is malformed")
                transport = str(target.get("transport") or "tcp").casefold()
                if transport != "tcp":
                    raise RescueError("TCP session target is not a TCP transport")
                details = self.backend.open_tcp(
                    session_id, str(target.get("host") or target.get("ip") or ""),
                    int(target.get("port") or 0), directory,
                )
            else:
                if target_index is not None:
                    raise RescueError("target-index is valid only for tcp sessions")
                if not argv:
                    raise RescueError("PTY session requires a direct command argv")
                details = self.backend.open_pty(session_id, normalized_kind, argv, directory)
            state.update(details)
            state["status"] = "RUNNING"
            state["updated_at"] = utc_now()
            atomic_json(directory / "SESSION_STATE.json", state)
            receipt = self._event("SESSION_OPENED", state, {
                "name": name, "argv": state.get("argv"), "target_index": target_index,
                "backend": state.get("backend"),
            })
            self._transcript(directory, "OPEN", {"receipt_id": receipt["receipt_id"]})
            record_telemetry(self.root, "persistent_session_opened", details={
                "session_id": session_id, "session_kind": normalized_kind,
                "session_receipt_id": receipt["receipt_id"],
            })
            return {**state, "session_receipt_id": receipt["receipt_id"]}
        except Exception as exc:
            state["status"] = "ERROR"; state["error"] = str(exc)[:2000]; state["updated_at"] = utc_now()
            atomic_json(directory / "SESSION_STATE.json", state)
            self._event("SESSION_ERROR", state, {"error": state["error"], "phase": "open"})
            raise

    def send(self, session_id: str, data: bytes, *, encoding: str) -> dict[str, Any]:
        directory, state = self._load(session_id)
        current = self.status(session_id)
        if current["status"] != "RUNNING":
            raise RescueError("session input requires a RUNNING session")
        if len(data) > 4 * 1024 * 1024:
            raise RescueError("session input exceeds 4 MiB")
        digest = hashlib.sha256(data).hexdigest()
        if state.get("backend") == "tmux":
            self.backend.send_pty(session_id, data)
        elif state.get("backend") == "python-socket-relay":
            self.backend.send_tcp(directory, data)
        else:
            raise RescueError("session backend is unsupported")
        receipt = self._event("SESSION_INPUT_SENT", state, {
            "encoding": encoding, "byte_count": len(data), "input_digest": digest,
        })
        self._transcript(directory, "INPUT", {
            "encoding": encoding, "byte_count": len(data), "sha256": digest,
            "receipt_id": receipt["receipt_id"],
        })
        return {
            **self._identity(), "session_id": session_id, "bytes_sent": len(data),
            "input_digest": digest, "session_receipt_id": receipt["receipt_id"],
        }

    def read(
        self, session_id: str, *, cursor: int, max_bytes: int = 32768,
        wait_seconds: float = 0,
    ) -> dict[str, Any]:
        directory, state = self._load(session_id)
        if not isinstance(cursor, int) or isinstance(cursor, bool) or cursor < 0:
            raise RescueError("session cursor must be a non-negative integer")
        if not 1 <= max_bytes <= MAX_READ_BYTES or not 0 <= wait_seconds <= 10:
            raise RescueError("session read bounds are invalid")
        deadline = time.monotonic() + wait_seconds
        while True:
            base, size = self._spool_position(directory)
            end = base + size
            if cursor < end or time.monotonic() >= deadline:
                break
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
        truncated = cursor < base
        effective = max(cursor, base)
        offset = effective - base
        with (directory / "stdout.bin").open("rb") as handle:
            handle.seek(offset)
            output = handle.read(max_bytes)
        cursor_after = effective + len(output)
        available_after = end - cursor_after
        evidence = self.root / "evidence" / "sessions" / session_id / f"{effective}-{cursor_after}.bin"
        evidence.parent.mkdir(parents=True, exist_ok=True)
        with evidence.open("wb") as handle:
            handle.write(output); handle.flush()
        output_digest = hashlib.sha256(output).hexdigest()
        after_counters = self._network_counters()
        network = protocol_network_observation(
            state.get("network_counters"), after_counters,
            list(self.metadata.get("authorized_targets") or []),
        )
        state["network_counters"] = after_counters
        state["updated_at"] = utc_now()
        atomic_json(directory / "SESSION_STATE.json", state)
        material = {
            "cursor_before": cursor, "cursor_effective": effective,
            "cursor_after": cursor_after, "output_digest": output_digest,
            "byte_count": len(output), "truncated": truncated or available_after > 0,
            "eof": self.status(session_id, record_exit=False)["status"] in {"EXITED", "CLOSED", "STALE", "ERROR"},
            "evidence_path": evidence.relative_to(self.root).as_posix(),
            "evidence_digest": sha256_file(evidence), "network_observation": network,
            "authorized_network_observed": any(row.get("observed") is True for row in network),
            "authorized_network_target_indices": [row["target_index"] for row in network if row.get("observed") is True],
            "artifact_snapshot": artifact_snapshot(self.root),
            "argv": list(state.get("argv") or []),
        }
        receipt = self._event("SESSION_OUTPUT_OBSERVED", state, material)
        receipt["observation_receipt_id"] = receipt["receipt_id"]
        # The execution receipt ID must be present in the canonical ledger row.
        self._replace_last_observation_id(receipt)
        self._transcript(directory, "OUTPUT", {
            "cursor_before": cursor, "cursor_after": cursor_after,
            "byte_count": len(output), "sha256": output_digest,
            "observation_receipt_id": receipt["receipt_id"],
        })
        if material["authorized_network_observed"]:
            telemetry = self.root / "RESCUE_TELEMETRY.jsonl"
            rows = read_jsonl_strict(telemetry, "rescue telemetry ledger") if telemetry.exists() else []
            if not any(row.get("event") == "first_remote_interaction" for row in rows):
                record_telemetry(self.root, "first_remote_interaction", details={
                    "execution_receipt_id": receipt["receipt_id"], "source": "persistent-session",
                })
        try:
            stdout = output.decode("utf-8")
            stdout_base64 = None
        except UnicodeDecodeError:
            stdout = None
            stdout_base64 = base64.b64encode(output).decode("ascii")
        return {
            **self._identity(), "session_id": session_id,
            "cursor_before": cursor, "cursor_after": cursor_after,
            "stdout": stdout, "stdout_base64": stdout_base64,
            "truncated": material["truncated"], "eof": material["eof"],
            "observation_receipt_id": receipt["receipt_id"],
            "network_observation": network,
        }

    def status(self, session_id: str, *, record_exit: bool = True) -> dict[str, Any]:
        directory, state = self._load(session_id)
        if state.get("status") in {"CLOSED", "STALE", "ERROR"}:
            return dict(state)
        try:
            observed = self.backend.status(state, directory)
        except RescueError as exc:
            observed = {"status": "STALE", "backend_detail": str(exc)}
        previous = state.get("status")
        state.update(observed); state["updated_at"] = utc_now()
        atomic_json(directory / "SESSION_STATE.json", state)
        if record_exit and previous == "RUNNING" and state.get("status") == "EXITED":
            self._event("SESSION_EXITED", state, {
                "exit_code": state.get("exit_code"), "backend_detail": state.get("backend_detail"),
            })
        return dict(state)

    def close(self, session_id: str) -> dict[str, Any]:
        directory, state = self._load(session_id)
        if state.get("status") == "CLOSED":
            return {**state, "idempotent": True}
        cleanup = self.backend.close(state, directory)
        if cleanup.get("remaining_processes"):
            state["status"] = "ERROR"; state["error"] = "session child processes remain after close"
            atomic_json(directory / "SESSION_STATE.json", state)
            self._event("SESSION_ERROR", state, {"phase": "close", "cleanup": cleanup})
            raise RescueError("persistent session process-group cleanup failed")
        state["status"] = "CLOSED"; state["closed_at"] = utc_now(); state["updated_at"] = state["closed_at"]
        state["cleanup"] = cleanup
        atomic_json(directory / "SESSION_STATE.json", state)
        receipt = self._event("SESSION_CLOSED", state, {"cleanup": cleanup})
        self._transcript(directory, "CLOSE", {"receipt_id": receipt["receipt_id"]})
        return {**state, "session_receipt_id": receipt["receipt_id"], "idempotent": False}

    def close_all(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for row in self.list()["sessions"]:
            if row.get("status") not in {"CLOSED", "STALE"}:
                results.append(self.close(str(row["session_id"])))
        return results

    def mark_all_stale(self, reason: str) -> int:
        count = 0
        for directory in sorted(self.sessions_root.iterdir()):
            if not directory.is_dir() or directory.is_symlink():
                continue
            try:
                _, state = self._load(directory.name)
            except RescueError:
                continue
            if state.get("status") not in {"CLOSED", "STALE"}:
                state["status"] = "STALE"; state["stale_reason"] = reason[:1000]; state["updated_at"] = utc_now()
                atomic_json(directory / "SESSION_STATE.json", state); count += 1
        return count

    def _load(self, session_id: str) -> tuple[Path, dict[str, Any]]:
        if not session_id.startswith("session-") or not _NAME.fullmatch(session_id):
            raise RescueError("session ID is invalid")
        directory = self.sessions_root / session_id
        state_path = directory / "SESSION_STATE.json"
        if directory.is_symlink() or not directory.is_dir() or state_path.is_symlink() or not state_path.is_file():
            raise RescueError("session does not exist in this rescue")
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RescueError("session state is malformed") from exc
        if any(state.get(key) != value for key, value in self._identity().items()):
            raise RescueError("session exact ownership mismatch")
        if state.get("session_id") != session_id or state.get("status") not in SESSION_STATES:
            raise RescueError("session state identity or status is malformed")
        return directory, state

    def _event(
        self, event: str, state: Mapping[str, Any], details: Mapping[str, Any],
    ) -> dict[str, Any]:
        if event not in SESSION_EVENTS:
            raise RescueError("session event is unsupported")
        ledger = self.root / "RESCUE_SESSIONS.jsonl"
        if ledger.exists() and ledger.stat().st_size > MAX_SESSION_LEDGER_BYTES:
            raise RescueError("rescue session ledger reached its bounded limit")
        row = {
            "schema_version": 1, "event": event, **self._identity(),
            "session_id": state["session_id"], "session_kind": state["session_kind"],
            "container_name": self.metadata.get("name"),
            "sandbox_image_id": self.metadata.get("actual_image_id"),
            "sandbox_image_digests": list(self.metadata.get("image_repo_digests") or []),
            "authorized_targets": list(self.metadata.get("authorized_targets") or []),
            **dict(details), "created_at": utc_now(),
        }
        row["receipt_id"] = hashlib.sha256(canonical_json(row)).hexdigest()[:24]
        if event == "SESSION_OUTPUT_OBSERVED":
            row["observation_receipt_id"] = row["receipt_id"]
        append_jsonl_fsync(ledger, row, label="rescue session ledger")
        return row

    def _replace_last_observation_id(self, receipt: Mapping[str, Any]) -> None:
        # append_jsonl is immutable; write a small second canonical alias event is
        # unnecessary.  The receipt ID itself is the observation receipt ID, and
        # readers accept either field.  This method exists to make that contract
        # explicit without rewriting the append-only ledger.
        return None

    def _identity(self) -> dict[str, Any]:
        identity = self.packet.get("identity")
        if not isinstance(identity, Mapping):
            raise RescueError("rescue packet identity is malformed")
        return {
            "run_id": identity.get("run_id"),
            "rescue_attempt_id": identity.get("rescue_attempt_id"),
            "packet_digest": self.packet.get("packet_digest"),
            "target_revision": identity.get("target_revision"),
            "input_fingerprint": identity.get("input_fingerprint"),
        }

    def _network_counters(self) -> dict[str, Any] | None:
        targets = list(self.metadata.get("authorized_targets") or [])
        if not targets:
            return None
        return firewall_counters(str(self.metadata["name"]), self.docker, targets)

    def _spool_position(self, directory: Path) -> tuple[int, int]:
        base_path = directory / "control" / "cursor_base"
        try:
            base = int(base_path.read_text(encoding="ascii").strip() or "0")
        except (OSError, ValueError):
            base = 0
        return base, (directory / "stdout.bin").stat().st_size

    def _transcript(self, directory: Path, event: str, details: Mapping[str, Any]) -> None:
        transcript = directory / "transcript.jsonl"
        if transcript.exists() and transcript.stat().st_size > MAX_SESSION_TRANSCRIPT_BYTES:
            raise RescueError("persistent session transcript reached its bounded limit")
        append_jsonl_fsync(transcript, {
            "schema_version": 1, "event": event, "details": dict(details), "created_at": utc_now(),
        }, label="session transcript")
