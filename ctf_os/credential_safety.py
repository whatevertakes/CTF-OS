"""Keep host and provider credentials outside challenge execution records.

The sandbox receives an explicit environment rather than the host process
environment.  These helpers enforce that boundary before an operation can be
serialized to RPC files or Docker argv, and expose only the values needed for
the host-side post-run contamination audit.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence

CREDENTIAL_KEY_PATTERN = (
    r"(?:[A-Za-z][A-Za-z0-9]*[_-])*"
    r"(?:"
    r"authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|"
    r"password|passwd|secret|client[_-]?secret|api[_-]?key|"
    r"access[_-]?(?:key|token)|refresh[_-]?token|auth[_-]?token|"
    r"token|credential(?:s)?|private[_-]?key|"
    r"pat|capability|"
    r"session(?:[_-]?(?:id|key|token|cookie|secret))?"
    r")"
)

_SENSITIVE_ENV_NAME = re.compile(
    rf"^(?:{CREDENTIAL_KEY_PATTERN}|"
    r"(?:DATABASE|DB|REDIS|POSTGRES(?:QL)?|MYSQL|MONGODB)_URL|"
    r"[A-Za-z][A-Za-z0-9_]*(?:_DSN|_CONNECTION_STRING)|"
    r"DOCKER_AUTH_CONFIG|NETRC)$",
    flags=re.IGNORECASE,
)
KNOWN_PROVIDER_CREDENTIAL = re.compile(
    r"(?i)\b(?:"
    r"sk-(?:proj-)?[A-Za-z0-9_-]{16,}|"
    r"sk_(?:live|test)_[A-Za-z0-9]{16,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{16,}|"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{30,}"
    r")\b"
)
_MIN_HOST_CREDENTIAL_CHARS = 8
_MODEL_ENVIRONMENT_NAMES = frozenset(
    {
        "COLORTERM",
        "HOME",
        "LANG",
        "LANGUAGE",
        "LOGNAME",
        "NO_COLOR",
        "PATH",
        "SHELL",
        "TERM",
        "TMPDIR",
        "TZ",
        "USER",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "NODE_EXTRA_CA_CERTS",
        "REQUESTS_CA_BUNDLE",
    }
)
_MODEL_PROVIDER_ENVIRONMENT_PREFIXES = (
    "OPENAI_",
    "CODEX_",
    "AZURE_OPENAI_",
)
_PROVIDER_BYTES = re.compile(
    KNOWN_PROVIDER_CREDENTIAL.pattern.encode("ascii"),
    KNOWN_PROVIDER_CREDENTIAL.flags & ~re.UNICODE,
)


class CredentialSafetyError(ValueError):
    """A command would expose credentials across the sandbox boundary."""


def is_sensitive_environment_name(name: str) -> bool:
    return bool(
        isinstance(name, str)
        and _SENSITIVE_ENV_NAME.fullmatch(name)
    )


def host_credential_values(
    environment: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Return distinct long credential values without exposing their names."""

    source = os.environ if environment is None else environment
    values = {
        value
        for name, value in source.items()
        if (
            is_sensitive_environment_name(name)
            and isinstance(value, str)
            and len(value) >= _MIN_HOST_CREDENTIAL_CHARS
        )
    }
    return tuple(sorted(values, key=lambda value: (-len(value), value)))


def model_process_environment(
    environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return the minimal host environment needed by a trusted model CLI."""

    source = os.environ if environment is None else environment
    return {
        name: value
        for name, value in source.items()
        if (
            name in _MODEL_ENVIRONMENT_NAMES
            or name.startswith("LC_")
            or name.startswith(_MODEL_PROVIDER_ENVIRONMENT_PREFIXES)
        )
    }


def credential_byte_patterns(
    credentials: Sequence[str],
) -> tuple[bytes, ...]:
    """Return raw and JSON-escaped encodings of protected values."""

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


def redact_credential_bytes(
    payload: bytes,
    credentials: Sequence[str],
) -> tuple[bytes, int]:
    """Redact exact and known-provider credentials from a byte payload."""

    redacted = payload
    count = 0
    for pattern in credential_byte_patterns(credentials):
        occurrences = redacted.count(pattern)
        if occurrences:
            redacted = redacted.replace(pattern, b"*" * len(pattern))
            count += occurrences

    def replace_provider(match: re.Match[bytes]) -> bytes:
        nonlocal count
        count += 1
        return b"*" * len(match.group(0))

    return _PROVIDER_BYTES.sub(replace_provider, redacted), count


def payload_contains_credentials(
    payload: bytes,
    credentials: Sequence[str],
) -> bool:
    """Return whether a byte payload contains a protected value."""

    _, count = redact_credential_bytes(payload, credentials)
    return bool(count)


def redact_exact_credentials(
    value: str,
    credentials: Sequence[str],
) -> tuple[str, int]:
    """Replace exact protected values while preserving flag-like data."""

    redacted = value
    count = 0
    for credential in sorted(
        {item for item in credentials if item},
        key=lambda item: (-len(item), item),
    ):
        occurrences = redacted.count(credential)
        if occurrences:
            replacement = "*" * len(credential.encode("utf-8"))
            redacted = redacted.replace(credential, replacement)
            count += occurrences
    return redacted, count


def validate_command_credentials(
    argv: Sequence[str],
    environment: Mapping[str, str],
    *,
    host_environment: Mapping[str, str] | None = None,
) -> None:
    """Reject credentials before command metadata or RPC payloads exist."""

    sensitive_names = sorted(
        name for name in environment if is_sensitive_environment_name(name)
    )
    if sensitive_names:
        raise CredentialSafetyError(
            "credential environment variables are forbidden at the "
            "challenge boundary: "
            + ", ".join(sensitive_names[:8])
        )

    protected = host_credential_values(host_environment)
    values = (*argv, *environment.values())
    for value in values:
        if any(secret in value for secret in protected):
            raise CredentialSafetyError(
                "command contains a protected host credential"
            )

    if any(
        KNOWN_PROVIDER_CREDENTIAL.search(value)
        for value in values
    ):
        raise CredentialSafetyError(
            "command contains credential-bearing text"
        )


def validate_trusted_model_command_credentials(
    argv: Sequence[str],
    *,
    host_environment: Mapping[str, str] | None = None,
) -> None:
    """Audit trusted model-CLI argv without treating config nouns as data.

    Model command builders own option names and configuration assignments, so
    generic names such as ``session`` or ``token`` are not evidence that their
    values are credentials.  User-controlled prompt text is validated through
    :func:`validate_metadata_credentials`; this boundary rejects only exact
    host values and unmistakable provider-key shapes in trusted argv.
    """

    protected = host_credential_values(host_environment)
    for value in argv:
        if any(secret in value for secret in protected):
            raise CredentialSafetyError(
                "model command contains a protected host credential"
            )
        if KNOWN_PROVIDER_CREDENTIAL.search(value):
            raise CredentialSafetyError(
                "model command contains a provider credential"
            )


def validate_metadata_credentials(
    value: str,
    *,
    host_environment: Mapping[str, str] | None = None,
) -> None:
    """Reject credentials before user-controlled metadata is persisted."""

    protected = host_credential_values(host_environment)
    if any(secret in value for secret in protected):
        raise CredentialSafetyError(
            "metadata contains a protected host credential"
        )
    if KNOWN_PROVIDER_CREDENTIAL.search(value):
        raise CredentialSafetyError(
            "metadata contains credential-bearing text"
        )


__all__ = [
    "CREDENTIAL_KEY_PATTERN",
    "CredentialSafetyError",
    "KNOWN_PROVIDER_CREDENTIAL",
    "host_credential_values",
    "is_sensitive_environment_name",
    "credential_byte_patterns",
    "model_process_environment",
    "payload_contains_credentials",
    "redact_credential_bytes",
    "redact_exact_credentials",
    "validate_command_credentials",
    "validate_metadata_credentials",
    "validate_trusted_model_command_credentials",
]
