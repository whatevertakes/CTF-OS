"""Fail-closed host credential audit for bounded ctfwrap run artifacts.

The normal boundary rejects host credentials before launch, so ctfwrap never
receives them.  If untrusted challenge input independently contains identical
bytes, ctfwrap can write a transient bounded copy before this host-side audit
runs.  The audit scrubs that copy before result promotion and rejects the run;
it does not claim the stronger guarantee of a host-owned streaming capture.
Real ctfwrap artifacts are created under umask 077.  The host audit also
accepts legacy owned read-only-to-peers fixtures, but never a group/world-
writable directory or file.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ctf_os.credential_safety import (
    KNOWN_PROVIDER_CREDENTIAL,
    host_credential_values,
)
from ctf_os.sandbox.files import DEFAULT_STREAM_CAPTURE_MAX_BYTES

_RUN_ID = re.compile(r"^run-[0-9]{8,}$")
_CONTROL_MAX_BYTES = 1024 * 1024
_RUN_FILE_LIMITS = {
    "flag-candidates.jsonl": _CONTROL_MAX_BYTES,
    "meta.json": _CONTROL_MAX_BYTES,
    "result.json": _CONTROL_MAX_BYTES,
    "stderr.log": DEFAULT_STREAM_CAPTURE_MAX_BYTES,
    "stdout.log": DEFAULT_STREAM_CAPTURE_MAX_BYTES,
    "stream-capture.json": _CONTROL_MAX_BYTES,
}
_PROVIDER_BYTES = re.compile(
    KNOWN_PROVIDER_CREDENTIAL.pattern.encode("ascii"),
    KNOWN_PROVIDER_CREDENTIAL.flags & ~re.UNICODE,
)


class OutputCredentialError(RuntimeError):
    """A run artifact is unsafe or contains a protected credential."""


@dataclass(frozen=True, slots=True)
class RunCredentialAudit:
    run_id: str
    redacted_files: tuple[str, ...]
    redaction_count: int

    @property
    def contaminated(self) -> bool:
        return bool(self.redacted_files)


def _artifact_label(name: str) -> str:
    return (
        "flag candidate sidecar"
        if name == "flag-candidates.jsonl"
        else name
    )


def _credential_patterns(credentials: tuple[str, ...]) -> tuple[bytes, ...]:
    patterns: set[bytes] = set()
    for credential in credentials:
        raw = credential.encode("utf-8")
        if raw:
            patterns.add(raw)
        for ensure_ascii in (False, True):
            escaped = json.dumps(
                credential,
                ensure_ascii=ensure_ascii,
            )[1:-1].encode("utf-8")
            if escaped:
                patterns.add(escaped)
    return tuple(sorted(patterns, key=lambda value: (-len(value), value)))


def _redact_payload(
    payload: bytes,
    *,
    exact_patterns: tuple[bytes, ...],
) -> tuple[bytes, int]:
    redacted = payload
    count = 0
    for pattern in exact_patterns:
        occurrences = redacted.count(pattern)
        if occurrences:
            redacted = redacted.replace(pattern, b"*" * len(pattern))
            count += occurrences

    def replace_provider(match: re.Match[bytes]) -> bytes:
        nonlocal count
        count += 1
        return b"*" * len(match.group(0))

    return _PROVIDER_BYTES.sub(replace_provider, redacted), count


def payload_contains_protected_credentials(
    payload: bytes,
    *,
    credentials: tuple[str, ...] | None = None,
) -> bool:
    """Return whether bounded control output contains a protected value."""

    protected = (
        host_credential_values()
        if credentials is None
        else tuple(credentials)
    )
    _, count = _redact_payload(
        payload,
        exact_patterns=_credential_patterns(protected),
    )
    return bool(count)


def _same_identity(
    left: os.stat_result,
    right: os.stat_result,
) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_uid,
        left.st_nlink,
        left.st_size,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_uid,
        right.st_nlink,
        right.st_size,
    )


def _same_snapshot(
    left: os.stat_result,
    right: os.stat_result,
) -> bool:
    return _same_identity(left, right) and (
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _open_private_directory(
    parent_descriptor: int,
    name: str,
    *,
    expected_device: int,
    label: str,
    missing_ok: bool,
) -> tuple[int, os.stat_result] | None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            name,
            flags,
            dir_fd=parent_descriptor,
        )
    except FileNotFoundError:
        if missing_ok:
            return None
        raise OutputCredentialError(f"{label} is missing") from None
    except OSError as error:
        raise OutputCredentialError(
            f"{label} cannot be opened without following links"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_dev != expected_device
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise OutputCredentialError(
                f"{label} is not an owned non-writable same-device directory"
            )
        return descriptor, metadata
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _verify_directory_binding(
    parent_descriptor: int,
    name: str,
    expected: os.stat_result,
    *,
    label: str,
) -> None:
    try:
        current = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        raise OutputCredentialError(
            f"{label} lineage cannot be revalidated"
        ) from error
    if not stat.S_ISDIR(current.st_mode) or not _same_snapshot(
        current,
        expected,
    ):
        raise OutputCredentialError(
            f"{label} lineage changed during credential audit"
        )


def _open_regular(
    run_descriptor: int,
    name: str,
    maximum_bytes: int,
    *,
    expected_device: int,
) -> tuple[int, bytes, os.stat_result]:
    label = _artifact_label(name)
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=run_descriptor)
    except OSError as error:
        raise OutputCredentialError(
            f"{label} cannot be opened for credential audit"
        ) from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != expected_device
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) & 0o022
            or opened.st_nlink != 1
            or opened.st_size > maximum_bytes
        ):
            raise OutputCredentialError(
                f"{label} is not an owned non-writable bounded single-link "
                "same-device run artifact"
            )
        payload = bytearray()
        offset = 0
        while offset < opened.st_size:
            block = os.pread(
                descriptor,
                min(1024 * 1024, opened.st_size - offset),
                offset,
            )
            if not block:
                raise OutputCredentialError(
                    f"{label} ended while being scanned"
                )
            payload.extend(block)
            offset += len(block)
        after = os.fstat(descriptor)
        if not _same_snapshot(opened, after):
            raise OutputCredentialError(
                f"{label} changed while being scanned"
            )
        return descriptor, bytes(payload), opened
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _rewrite_open_regular(
    descriptor: int,
    name: str,
    before: os.stat_result,
    payload: bytes,
) -> os.stat_result:
    label = _artifact_label(name)
    if len(payload) != before.st_size:
        raise OutputCredentialError(
            f"{label} redaction would change its bounded byte count"
        )
    current = os.fstat(descriptor)
    if not _same_snapshot(current, before):
        raise OutputCredentialError(
            f"{label} changed before credential redaction"
        )
    view = memoryview(payload)
    offset = 0
    try:
        while view:
            written = os.pwrite(descriptor, view, offset)
            if written <= 0:
                raise OSError("credential redaction write made no progress")
            view = view[written:]
            offset += written
        os.fsync(descriptor)
        verified = bytearray()
        verify_offset = 0
        while verify_offset < len(payload):
            block = os.pread(
                descriptor,
                min(1024 * 1024, len(payload) - verify_offset),
                verify_offset,
            )
            if not block:
                raise OutputCredentialError(
                    f"{label} ended while verifying redaction"
                )
            verified.extend(block)
            verify_offset += len(block)
        after = os.fstat(descriptor)
    except OSError as error:
        raise OutputCredentialError(
            f"{label} credential redaction failed"
        ) from error
    if (
        bytes(verified) != payload
        or not _same_identity(before, after)
    ):
        raise OutputCredentialError(
            f"{label} changed while credential redaction was committed"
        )
    return after


def _verify_regular_binding(
    run_descriptor: int,
    name: str,
    expected: os.stat_result,
) -> None:
    label = _artifact_label(name)
    try:
        current = os.stat(
            name,
            dir_fd=run_descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        raise OutputCredentialError(
            f"{label} binding cannot be revalidated"
        ) from error
    if not stat.S_ISREG(current.st_mode) or not _same_snapshot(
        current,
        expected,
    ):
        raise OutputCredentialError(
            f"{label} binding changed during credential audit"
        )


def _redact_capture_tail(
    payload: bytes,
    *,
    exact_patterns: tuple[bytes, ...],
) -> tuple[bytes, int]:
    try:
        document: Any = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise OutputCredentialError(
            "stream-capture.json is not valid JSON"
        ) from error
    streams = document.get("streams") if isinstance(document, dict) else None
    if not isinstance(streams, dict):
        raise OutputCredentialError(
            "stream-capture.json has no stream map"
    )
    count = 0
    redacted_payload = payload
    applied_replacements: dict[bytes, bytes] = {}
    for name in ("stdout", "stderr"):
        stream = streams.get(name)
        if not isinstance(stream, dict):
            continue
        tail_base64 = stream.get("tail_base64")
        if not isinstance(tail_base64, str):
            continue
        try:
            tail = base64.b64decode(tail_base64, validate=True)
        except (ValueError, binascii.Error) as error:
            raise OutputCredentialError(
                "stream-capture.json has invalid tail encoding"
            ) from error
        redacted, redactions = _redact_payload(
            tail,
            exact_patterns=exact_patterns,
        )
        if redactions:
            redacted_base64 = base64.b64encode(redacted).decode("ascii")
            original = tail_base64.encode("ascii")
            replacement = redacted_base64.encode("ascii")
            if len(original) != len(replacement):
                raise OutputCredentialError(
                    "stream-capture.json tail redaction changed length"
                )
            prior_replacement = applied_replacements.get(original)
            if prior_replacement is not None:
                if prior_replacement != replacement:
                    raise OutputCredentialError(
                        "stream-capture.json has conflicting tail bindings"
                    )
                count += redactions
                continue
            occurrences = redacted_payload.count(original)
            if not occurrences:
                raise OutputCredentialError(
                    "stream-capture.json tail binding changed"
                )
            redacted_payload = redacted_payload.replace(
                original,
                replacement,
            )
            applied_replacements[original] = replacement
            count += redactions
    if not count:
        return payload, 0
    if len(redacted_payload) != len(payload):
        raise OutputCredentialError(
            "stream-capture.json redaction changed its byte count"
        )
    return redacted_payload, count


def audit_run_output_credentials(
    work_dir: Path,
    run_id: str,
    *,
    credentials: tuple[str, ...] | None = None,
) -> RunCredentialAudit:
    """Scrub exact host/provider credentials, then report contamination.

    A contaminated audit is not a successful command result.  The caller must
    fail the operation after this function has replaced every retained copy.
    Ordinary CTF flag strings are not matched by this audit.  Traversal and
    writes remain anchored to no-follow directory/file descriptors so a
    challenge-controlled ancestor rename cannot redirect redaction outside
    the trusted work tree.
    """

    if not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None:
        raise OutputCredentialError("sandbox returned an invalid run id")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        work_descriptor = os.open(Path(work_dir), directory_flags)
    except OSError as error:
        raise OutputCredentialError(
            "trusted sandbox work directory cannot be opened"
        ) from error
    ctf_descriptor = -1
    runs_descriptor = -1
    run_descriptor = -1
    try:
        work_metadata = os.fstat(work_descriptor)
        if (
            not stat.S_ISDIR(work_metadata.st_mode)
            or work_metadata.st_uid != os.geteuid()
        ):
            raise OutputCredentialError(
                "trusted sandbox work directory has unsafe ownership"
            )
        expected_device = work_metadata.st_dev
        ctf_opened = _open_private_directory(
            work_descriptor,
            ".ctf",
            expected_device=expected_device,
            label="ctfwrap state directory",
            missing_ok=True,
        )
        if ctf_opened is None:
            # Test doubles and legacy alternate backends may not persist
            # ctfwrap artifacts. There is no raw file to contaminate.
            return RunCredentialAudit(run_id, (), 0)
        ctf_descriptor, ctf_metadata = ctf_opened
        runs_opened = _open_private_directory(
            ctf_descriptor,
            "runs",
            expected_device=expected_device,
            label="ctfwrap runs directory",
            missing_ok=True,
        )
        if runs_opened is None:
            return RunCredentialAudit(run_id, (), 0)
        runs_descriptor, runs_metadata = runs_opened
        run_opened = _open_private_directory(
            runs_descriptor,
            run_id,
            expected_device=expected_device,
            label="ctfwrap run directory",
            missing_ok=True,
        )
        if run_opened is None:
            return RunCredentialAudit(run_id, (), 0)
        run_descriptor, run_metadata = run_opened

        protected = (
            host_credential_values()
            if credentials is None
            else tuple(credentials)
        )
        patterns = _credential_patterns(protected)
        redacted_files: list[str] = []
        redaction_count = 0
        file_bindings: list[tuple[str, os.stat_result]] = []
        for name, maximum_bytes in _RUN_FILE_LIMITS.items():
            try:
                os.stat(
                    name,
                    dir_fd=run_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                continue
            except OSError as error:
                raise OutputCredentialError(
                    f"{_artifact_label(name)} cannot be inspected for "
                    "credentials"
                ) from error
            descriptor, payload, before = _open_regular(
                run_descriptor,
                name,
                maximum_bytes,
                expected_device=expected_device,
            )
            try:
                if name == "stream-capture.json":
                    payload, tail_redactions = _redact_capture_tail(
                        payload,
                        exact_patterns=patterns,
                    )
                else:
                    tail_redactions = 0
                redacted, direct_redactions = _redact_payload(
                    payload,
                    exact_patterns=patterns,
                )
                file_redactions = tail_redactions + direct_redactions
                if file_redactions:
                    binding = _rewrite_open_regular(
                        descriptor,
                        name,
                        before,
                        redacted,
                    )
                    redacted_files.append(name)
                    redaction_count += file_redactions
                else:
                    binding = before
                file_bindings.append((name, binding))
            finally:
                os.close(descriptor)

        for name, binding in file_bindings:
            _verify_regular_binding(run_descriptor, name, binding)
        _verify_directory_binding(
            runs_descriptor,
            run_id,
            run_metadata,
            label="ctfwrap run directory",
        )
        _verify_directory_binding(
            ctf_descriptor,
            "runs",
            runs_metadata,
            label="ctfwrap runs directory",
        )
        _verify_directory_binding(
            work_descriptor,
            ".ctf",
            ctf_metadata,
            label="ctfwrap state directory",
        )
        return RunCredentialAudit(
            run_id,
            tuple(redacted_files),
            redaction_count,
        )
    finally:
        for descriptor in (
            run_descriptor,
            runs_descriptor,
            ctf_descriptor,
            work_descriptor,
        ):
            if descriptor < 0:
                continue
            try:
                os.close(descriptor)
            except OSError:
                pass


__all__ = [
    "OutputCredentialError",
    "RunCredentialAudit",
    "audit_run_output_credentials",
    "payload_contains_protected_credentials",
]
