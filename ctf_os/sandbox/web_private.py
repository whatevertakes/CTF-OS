"""Private Web identity state for the typed HTTP/browser helper boundary.

The raw cookie store is never placed below a model workspace.  It is mounted
only for an exact, image-owned Web helper invocation.  Generic challenge
commands do not receive the mount.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .types import ChallengeScope


PRIVATE_WEB_SESSION_CONTAINER_ROOT = "/run/ctfos-web-session"
PRIVATE_WEB_SESSION_ROOT_ENV = "CTF_OS_WEB_PRIVATE_SESSION_ROOT"
PRIVATE_WEB_TIMELINE_CONTAINER_ROOT = "/run/ctfos-web-timeline"
PRIVATE_WEB_TIMELINE_ROOT_ENV = "CTF_OS_WEB_PRIVATE_TIMELINE_ROOT"
PRIVATE_WEB_DIRECTORY = "web-private-v1"
WEB_SESSION_NAMES = frozenset({"attacker", "user", "admin"})
_RUN_ID = re.compile(r"^run-[0-9]{8,}$")
_ALLOWED_HELPER_ENV = frozenset({"CTF_WRAP_FLAG_PATTERNS_JSON"})
_TRUSTED_HELPERS = {
    "/opt/ctf-templates/web/request.py": (
        "http",
        (
            "/opt/venvs/main/bin/python",
            "/opt/ctf-templates/web/request.py",
        ),
    ),
    "/opt/ctf-templates/web/browser.py": (
        "browser",
        (
            "/opt/venvs/pw/bin/python",
            "/opt/ctf-templates/web/browser.py",
        ),
    ),
    "/usr/local/bin/ctf-browser": (
        "browser",
        (
            "/opt/venvs/pw/bin/python",
            "/opt/ctf-templates/web/browser.py",
        ),
    ),
    "ctf-browser": (
        "browser",
        (
            "/opt/venvs/pw/bin/python",
            "/opt/ctf-templates/web/browser.py",
        ),
    ),
}
_PUBLIC_WEB_FILES = frozenset(
    {
        "body.bin",
        "body.txt",
        "browser.html",
        "browser.json",
        "error.json",
        "response.json",
        "timeline.json",
    }
)
_RUN_FILES = frozenset(
    {
        "flag-candidates.json",
        "result.json",
        "stderr.log",
        "stdout.log",
    }
)
_MAX_COOKIE_FILE_BYTES = 1024 * 1024
_MAX_COOKIE_COUNT = 256
_MAX_SECRET_BYTES = 16 * 1024
_MAX_REDACTION_FILE_BYTES = 512 * 1024 * 1024


class WebPrivateStateError(ValueError):
    """The private helper boundary or persisted jar is unsafe."""


@dataclass(frozen=True, slots=True)
class WebSessionCommand:
    kind: str
    session_name: str
    argv: tuple[str, ...]


def _private_owned_directory(
    path: Path,
    *,
    create: bool = False,
    private: bool = True,
) -> Path:
    if create:
        path.mkdir(mode=0o700, parents=False, exist_ok=True)
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise WebPrivateStateError(
            "private Web state directory is unavailable"
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or (
            stat.S_IMODE(metadata.st_mode)
            & (0o077 if private else 0o022)
        )
    ):
        raise WebPrivateStateError(
            "private Web state path has unsafe ownership or permissions"
        )
    flags = os.O_RDONLY | os.O_CLOEXEC
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise WebPrivateStateError(
            "private Web state directory cannot be opened safely"
        ) from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino)
            != (metadata.st_dev, metadata.st_ino)
        ):
            raise WebPrivateStateError(
                "private Web state directory changed while opening"
            )
    finally:
        os.close(descriptor)
    return path


def resolve_private_web_root(scope: ChallengeScope) -> Path:
    """Resolve one stable engine-owned directory from the canonical layout."""

    if scope.category != "web":
        raise WebPrivateStateError(
            "private Web state is available only for Web challenges"
        )
    challenge = scope.challenge_dir
    try:
        incoming_root = challenge.parents[2]
    except IndexError as error:
        raise WebPrivateStateError(
            "challenge input is outside the canonical incoming layout"
        ) from error
    expected = (
        incoming_root
        / scope.contest_id
        / scope.category
        / scope.challenge_id
    )
    if (
        incoming_root.name != "incoming"
        or expected.resolve(strict=True) != challenge
    ):
        raise WebPrivateStateError(
            "challenge input is outside the canonical incoming layout"
        )

    state_root = incoming_root.parent / ".ctfos"
    _private_owned_directory(state_root)
    challenge_state_root = (
        state_root
        / "contests"
        / scope.contest_id
        / "challenges"
        / scope.category
        / scope.challenge_id
    )
    try:
        resolved_challenge_state = challenge_state_root.resolve(strict=True)
    except OSError as error:
        raise WebPrivateStateError(
            "canonical challenge state directory is unavailable"
        ) from error
    if resolved_challenge_state not in scope.work_dir.parents:
        raise WebPrivateStateError(
            "sandbox workspace is outside its canonical challenge state"
        )
    _private_owned_directory(challenge_state_root, private=False)
    runtime_root = _private_owned_directory(
        challenge_state_root / "runtime",
        private=False,
    )
    private_root = runtime_root / PRIVATE_WEB_DIRECTORY
    try:
        private_root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as error:
        raise WebPrivateStateError(
            "private Web state directory cannot be created"
        ) from error
    try:
        os.chmod(private_root, 0o700, follow_symlinks=False)
    except OSError as error:
        raise WebPrivateStateError(
            "private Web state permissions cannot be enforced"
        ) from error
    return _private_owned_directory(private_root)


def _session_arguments(argv: Sequence[str]) -> tuple[str, ...]:
    values: list[str] = []
    for index, argument in enumerate(argv[1:], start=1):
        if argument == "--session":
            if index + 1 >= len(argv):
                raise WebPrivateStateError("--session requires one role")
            values.append(argv[index + 1])
        elif argument.startswith("--session="):
            values.append(argument.partition("=")[2])
    return tuple(values)


def prepare_web_session_command(
    *,
    category: str,
    argv: Sequence[str],
    environment: Mapping[str, str],
) -> WebSessionCommand | None:
    """Recognize only a direct invocation of one immutable image helper."""

    helper = _TRUSTED_HELPERS.get(argv[0]) if argv else None
    if (
        PRIVATE_WEB_SESSION_ROOT_ENV in environment
        or PRIVATE_WEB_TIMELINE_ROOT_ENV in environment
    ):
        raise WebPrivateStateError(
            "private Web mount environment variables are reserved for the "
            "engine"
        )
    if helper is None:
        return None
    sessions = _session_arguments(argv)
    if not sessions:
        return None
    if category != "web":
        raise WebPrivateStateError(
            "persistent Web sessions require a Web challenge"
        )
    if len(sessions) != 1 or sessions[0] not in WEB_SESSION_NAMES:
        raise WebPrivateStateError(
            "persistent Web helper requires exactly one valid session role"
        )
    unexpected_environment = sorted(
        set(environment) - _ALLOWED_HELPER_ENV
    )
    if unexpected_environment:
        raise WebPrivateStateError(
            "persistent Web helpers reject caller-provided environment "
            "variables: " + ", ".join(unexpected_environment)
        )
    kind, trusted_prefix = helper
    if kind == "browser" and any(
        value == "--screenshot" or value.startswith("--screenshot=")
        for value in argv[1:]
    ):
        raise WebPrivateStateError(
            "persistent browser screenshots are disabled because pixels "
            "cannot be checked for cookie disclosure"
        )
    if kind == "http":
        data_files: list[str] = []
        for index, value in enumerate(argv[1:], start=1):
            if value == "--data-file":
                if index + 1 >= len(argv):
                    raise WebPrivateStateError(
                        "--data-file requires one path"
                    )
                data_files.append(argv[index + 1])
            elif value.startswith("--data-file="):
                data_files.append(value.partition("=")[2])
        if len(data_files) > 1:
            raise WebPrivateStateError(
                "persistent HTTP helper accepts one data file"
            )
        for data_file in data_files:
            path = PurePosixPath(data_file)
            if "\x00" in data_file or ".." in path.parts:
                raise WebPrivateStateError(
                    "persistent HTTP data file escapes public inputs"
                )
            if path.is_absolute():
                if not path.parts or path.parts[1:2] not in {
                    ("challenge",),
                    ("work",),
                }:
                    raise WebPrivateStateError(
                        "persistent HTTP data file must be under "
                        "/challenge or /work"
                    )
    return WebSessionCommand(
        kind=kind,
        session_name=sessions[0],
        argv=(*trusted_prefix, *argv[1:]),
    )


def _read_cookie_file(path: Path, session_name: str) -> tuple[str, ...]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return ()
    except OSError as error:
        raise WebPrivateStateError("cookie jar cannot be opened safely") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > _MAX_COOKIE_FILE_BYTES
            or stat.S_IMODE(before.st_mode) & 0o077
        ):
            raise WebPrivateStateError("cookie jar is not a private bounded file")
        payload = bytearray()
        while len(payload) <= _MAX_COOKIE_FILE_BYTES:
            block = os.read(
                descriptor,
                min(
                    64 * 1024,
                    _MAX_COOKIE_FILE_BYTES + 1 - len(payload),
                ),
            )
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
        if (
            len(payload) > _MAX_COOKIE_FILE_BYTES
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise WebPrivateStateError("cookie jar changed while being read")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(bytes(payload))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WebPrivateStateError("cookie jar is not valid JSON") from error
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("session") != session_name
        or not isinstance(value.get("cookies"), list)
        or len(value["cookies"]) > _MAX_COOKIE_COUNT
    ):
        raise WebPrivateStateError("cookie jar envelope is invalid")
    secrets: list[str] = []
    for cookie in value["cookies"]:
        if not isinstance(cookie, dict) or not isinstance(cookie.get("value"), str):
            raise WebPrivateStateError("cookie jar entry is invalid")
        secret = cookie["value"]
        if len(secret.encode("utf-8")) > _MAX_SECRET_BYTES:
            raise WebPrivateStateError("cookie value exceeds its bound")
        if secret:
            secrets.append(secret)
    return tuple(secrets)


def resolve_private_web_mounts(
    scope: ChallengeScope,
    session_name: str,
) -> tuple[Path, Path]:
    """Return one role-only cookie mount and one value-free timeline mount."""

    if session_name not in WEB_SESSION_NAMES:
        raise WebPrivateStateError("invalid private Web session role")
    private_root = resolve_private_web_root(scope)
    sessions_root = private_root / "sessions"
    timeline_root = private_root / "timeline"
    for path in (sessions_root, timeline_root):
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError as error:
            raise WebPrivateStateError(
                "private Web state subdirectory cannot be created"
            ) from error
        try:
            os.chmod(path, 0o700, follow_symlinks=False)
        except OSError as error:
            raise WebPrivateStateError(
                "private Web state subdirectory permissions cannot be "
                "enforced"
            ) from error
        _private_owned_directory(path)
    session_root = sessions_root / session_name
    try:
        session_root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as error:
        raise WebPrivateStateError(
            "private Web role directory cannot be created"
        ) from error
    try:
        os.chmod(session_root, 0o700, follow_symlinks=False)
    except OSError as error:
        raise WebPrivateStateError(
            "private Web role permissions cannot be enforced"
        ) from error
    return _private_owned_directory(session_root), timeline_root


def snapshot_cookie_values(
    private_session_root: Path,
    session_name: str,
) -> tuple[str, ...]:
    _private_owned_directory(private_session_root)
    values = _read_cookie_file(
        private_session_root / "cookies.json",
        session_name,
    )
    return tuple(sorted(set(values), key=lambda value: (-len(value), value)))


def snapshot_all_cookie_values(private_root: Path) -> tuple[str, ...]:
    """Read every role jar on the host without mounting sibling roles."""

    _private_owned_directory(private_root)
    values: set[str] = set()
    for session_name in sorted(WEB_SESSION_NAMES):
        session_root = private_root / "sessions" / session_name
        try:
            session_root.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        values.update(snapshot_cookie_values(session_root, session_name))
    return tuple(sorted(values, key=lambda value: (-len(value), value)))


def _secret_byte_patterns(secrets: Sequence[str]) -> tuple[bytes, ...]:
    patterns: set[bytes] = set()
    for secret in secrets:
        raw = secret.encode("utf-8")
        if not raw:
            continue
        patterns.add(raw)
        escaped = json.dumps(secret, ensure_ascii=False)[1:-1].encode("utf-8")
        if escaped:
            patterns.add(escaped)
    return tuple(sorted(patterns, key=lambda value: (-len(value), value)))


def redact_value(value: Any, secrets: Sequence[str]) -> Any:
    """Return a shape-preserving copy without exact secret strings."""

    if isinstance(value, str):
        redacted = value
        for secret in sorted(set(secrets), key=lambda item: (-len(item), item)):
            if secret:
                redacted = redacted.replace(
                    secret,
                    "*" * len(secret.encode("utf-8")),
                )
        return redacted
    if isinstance(value, list):
        return [redact_value(item, secrets) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item, secrets) for item in value)
    if isinstance(value, dict):
        return {
            key: redact_value(item, secrets)
            for key, item in value.items()
        }
    return value


def _redact_regular(path: Path, patterns: Sequence[bytes]) -> None:
    try:
        before = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as error:
        raise WebPrivateStateError("public Web artifact cannot be inspected") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > _MAX_REDACTION_FILE_BYTES
    ):
        raise WebPrivateStateError(
            "public Web artifact is not a bounded single-link regular file"
        )
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                (opened.st_dev, opened.st_ino, opened.st_size)
                != (before.st_dev, before.st_ino, before.st_size)
            ):
                raise WebPrivateStateError(
                    "public Web artifact changed while opening"
                )
            payload = bytearray()
            while len(payload) <= _MAX_REDACTION_FILE_BYTES:
                block = os.read(
                    descriptor,
                    min(
                        1024 * 1024,
                        _MAX_REDACTION_FILE_BYTES + 1 - len(payload),
                    ),
                )
                if not block:
                    break
                payload.extend(block)
            after = os.fstat(descriptor)
            if (
                len(payload) > _MAX_REDACTION_FILE_BYTES
                or (opened.st_size, opened.st_mtime_ns)
                != (after.st_size, after.st_mtime_ns)
            ):
                raise WebPrivateStateError(
                    "public Web artifact changed while being read"
                )
        finally:
            os.close(descriptor)
    except OSError as error:
        raise WebPrivateStateError(
            "public Web artifact cannot be read safely"
        ) from error

    redacted = bytes(payload)
    for pattern in patterns:
        redacted = redacted.replace(pattern, b"*" * len(pattern))
    if redacted == payload:
        return
    temporary = path.with_name(
        f".{path.name}.web-redact-{os.getpid()}-{os.urandom(6).hex()}"
    )
    write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    write_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        output = os.open(
            temporary,
            write_flags,
            stat.S_IMODE(before.st_mode) & 0o700,
        )
        try:
            view = memoryview(redacted)
            while view:
                written = os.write(output, view)
                if written <= 0:
                    raise OSError("redaction write made no progress")
                view = view[written:]
            os.fsync(output)
        finally:
            os.close(output)
        current = path.stat(follow_symlinks=False)
        if (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ):
            raise WebPrivateStateError(
                "public Web artifact changed before redaction commit"
            )
        os.replace(temporary, path)
        directory_flags = os.O_RDONLY | os.O_CLOEXEC
        directory_flags |= getattr(os, "O_DIRECTORY", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0)
        parent_descriptor = os.open(path.parent, directory_flags)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def redact_private_timeline(
    private_timeline_root: Path,
    secrets: Sequence[str],
) -> None:
    """Keep the shared durable timeline value-free across role changes."""

    _private_owned_directory(private_timeline_root)
    lock_path = private_timeline_root / ".timeline.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as error:
        raise WebPrivateStateError(
            "private Web timeline lock cannot be opened safely"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise WebPrivateStateError("private Web timeline lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        patterns = _secret_byte_patterns(secrets)
        if patterns:
            _redact_regular(
                private_timeline_root / "timeline.json",
                patterns,
            )
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def snapshot_run_ids(work_dir: Path) -> frozenset[str]:
    runs = work_dir / ".ctf" / "runs"
    try:
        return frozenset(
            item.name
            for item in runs.iterdir()
            if _RUN_ID.fullmatch(item.name) and item.is_dir()
        )
    except FileNotFoundError:
        return frozenset()
    except OSError as error:
        raise WebPrivateStateError(
            "Web helper run directory cannot be inspected"
        ) from error


def redact_public_artifacts(
    work_dir: Path,
    *,
    previous_run_ids: frozenset[str],
    secrets: Sequence[str],
) -> None:
    """Scrub exact cookie values before the sandbox result is returned."""

    patterns = _secret_byte_patterns(secrets)
    if not patterns:
        return
    web_root = work_dir / "web"
    for name in sorted(_PUBLIC_WEB_FILES):
        _redact_regular(web_root / name, patterns)
    for run_id in sorted(snapshot_run_ids(work_dir) - previous_run_ids):
        run_root = work_dir / ".ctf" / "runs" / run_id
        for name in sorted(_RUN_FILES):
            _redact_regular(run_root / name, patterns)


def discard_public_artifacts(
    work_dir: Path,
    *,
    previous_run_ids: frozenset[str],
) -> None:
    """Remove exact helper outputs when post-run secret audit cannot finish."""

    paths = [
        *(work_dir / "web" / name for name in sorted(_PUBLIC_WEB_FILES)),
    ]
    for run_id in sorted(snapshot_run_ids(work_dir) - previous_run_ids):
        paths.extend(
            work_dir / ".ctf" / "runs" / run_id / name
            for name in sorted(_RUN_FILES)
        )
    failures: list[str] = []
    for path in paths:
        try:
            metadata = path.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as error:
            failures.append(f"{path.name}: {error}")
            continue
        if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
            failures.append(f"{path.name}: unexpected file type")
            continue
        try:
            path.unlink()
        except OSError as error:
            failures.append(f"{path.name}: {error}")
    if failures:
        raise WebPrivateStateError(
            "failed to discard unaudited Web helper outputs: "
            + "; ".join(failures[:8])
        )


__all__ = [
    "PRIVATE_WEB_SESSION_CONTAINER_ROOT",
    "PRIVATE_WEB_SESSION_ROOT_ENV",
    "PRIVATE_WEB_TIMELINE_CONTAINER_ROOT",
    "PRIVATE_WEB_TIMELINE_ROOT_ENV",
    "WebPrivateStateError",
    "WebSessionCommand",
    "prepare_web_session_command",
    "discard_public_artifacts",
    "redact_public_artifacts",
    "redact_private_timeline",
    "redact_value",
    "resolve_private_web_mounts",
    "resolve_private_web_root",
    "snapshot_cookie_values",
    "snapshot_all_cookie_values",
    "snapshot_run_ids",
]
