"""Shared typed contracts for challenge-scoped sandbox operations."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PureWindowsPath
from types import MappingProxyType

from ctf_os.director.resources import ResourceVector
from ctf_os.sandbox.files import (
    DEFAULT_SNAPSHOT_MAX_BYTES,
    SafeFileError,
    normalize_locator,
)

ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
JOB_ID = re.compile(r"^job-[0-9]{8}$")


def validate_deadline_monotonic_seconds(
    value: int | float | None,
) -> float | None:
    """Validate one absolute same-host monotonic deadline."""

    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or value <= 0
    ):
        raise ValueError(
            "deadline_monotonic_seconds must be positive and finite"
        )
    return float(value)


class SandboxError(RuntimeError):
    """An expected sandbox boundary failure."""


class ScopeError(SandboxError):
    """A challenge scope or scoped reference is invalid."""


class NetworkDenied(SandboxError):
    """A command requested network access outside the explicit policy."""


class BackgroundJobUnsupported(SandboxError):
    """A background start was requested without a lease supervisor."""


_BACKGROUND_STARTERS = frozenset(
    {
        "ctf-bg",
        "coproc",
        "daemon",
        "nohup",
        "setsid",
        "start-stop-daemon",
        "systemd-run",
    }
)
_SHELL_ENTRYPOINTS = frozenset({"ash", "bash", "dash", "sh", "zsh"})
_SHELL_COMMAND_BOUNDARIES = frozenset(
    {"\n", ";", ";;", "&&", "||", "|", "(", ")"}
)
_SHELL_REDIRECTIONS = frozenset(
    {
        "<",
        ">",
        "<<",
        "<<-",
        "<<<",
        ">>",
        "<&",
        ">&",
        "<>",
        ">|",
        "&>",
        "&>>",
    }
)
_SHELL_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_SHELL_DOUBLE_QUOTE_ESCAPES = frozenset({'$', '`', '"', "\\"})
_SHELL_RESERVED_COMMAND_PREFIXES = frozenset(
    {"if", "then", "elif", "else", "while", "until", "do"}
)
_ENV_OPTIONS_WITHOUT_ARGUMENT = frozenset(
    {
        "-",
        "-0",
        "-i",
        "-v",
        "--debug",
        "--block-signal",
        "--default-signal",
        "--ignore-environment",
        "--ignore-signal",
        "--null",
    }
)
_ENV_OPTIONS_WITH_ARGUMENT = frozenset(
    {
        "-C",
        "-u",
        "--argv0",
        "--chdir",
        "--unset",
    }
)
_ENV_ATTACHED_OPTION_PREFIXES = (
    "--argv0=",
    "--block-signal=",
    "--chdir=",
    "--default-signal=",
    "--ignore-signal=",
    "--unset=",
)
_SHELL_NESTING_LIMIT = 8
_SHELL_TOKEN_LIMIT = 65_536
_SHELL_AMBIGUOUS_EXPANSION = "<ambiguous-shell-expansion>"
_SHELL_COMMAND_SUBSTITUTION = "<shell-command-substitution>"
_SHELL_PROCESS_SUBSTITUTION = "<shell-process-substitution>"


@dataclass(frozen=True, slots=True)
class _ShellToken:
    value: str
    operator: bool = False
    quoted: bool = False
    nested_script: str | None = None


def _shell_heredoc_delimiters(
    line_tokens: Sequence[_ShellToken],
) -> tuple[tuple[str, bool, bool], ...]:
    delimiters: list[tuple[str, bool, bool]] = []
    pending: list[bool] = []
    for token in line_tokens:
        if token.operator and token.value in {"<<", "<<-"}:
            pending.append(token.value == "<<-")
            continue
        if token.operator:
            if token.value in _SHELL_COMMAND_BOUNDARIES:
                pending.clear()
            continue
        if pending:
            for strip_tabs in pending:
                delimiters.append(
                    (
                        token.value,
                        strip_tabs,
                        token.quoted,
                    )
                )
            pending.clear()
    return tuple(delimiters)


def _append_shell_token(
    tokens: list[_ShellToken],
    token: _ShellToken,
    *,
    limit: int = _SHELL_TOKEN_LIMIT,
) -> None:
    if len(tokens) >= limit:
        raise BackgroundJobUnsupported(
            "shell command exceeds the foreground lexical token limit"
        )
    tokens.append(token)


def _parse_shell_heredoc_delimiter(
    value: str,
    start: int,
) -> tuple[str, bool, int] | None:
    index = start
    while index < len(value) and value[index] in {" ", "\t"}:
        index += 1
    if index >= len(value) or value[index] == "\n":
        return None
    delimiter: list[str] = []
    quoted = False
    started = False
    quote: str | None = None
    while index < len(value):
        character = value[index]
        if quote == "'":
            started = True
            if character == "'":
                quote = None
            else:
                delimiter.append(character)
            index += 1
            continue
        if quote == '"':
            started = True
            if character == '"':
                quote = None
            elif character == "\\" and index + 1 < len(value):
                following = value[index + 1]
                if following == "\n":
                    index += 2
                    continue
                if following in _SHELL_DOUBLE_QUOTE_ESCAPES:
                    delimiter.append(following)
                else:
                    delimiter.extend(("\\", following))
                index += 2
                continue
            else:
                delimiter.append(character)
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            quoted = True
            started = True
            index += 1
            continue
        if character == "\\" and index + 1 < len(value):
            delimiter.append(value[index + 1])
            quoted = True
            started = True
            index += 2
            continue
        if character.isspace() or character in ";&|()<>":
            break
        delimiter.append(character)
        started = True
        index += 1
    if not started or quote is not None:
        return None
    return "".join(delimiter), quoted, index


def _extract_arithmetic_expansion(
    value: str,
    start: int,
) -> int | None:
    """Return the exclusive end of one literal balanced ``$((...))``.

    Arithmetic operators are not shell job-control operators.  The body stays
    opaque to the shell-command classifier, but command substitutions,
    backticks, quotes, and malformed nesting fail closed.
    """

    if not value.startswith("$((", start):
        return None
    depth = 0
    index = start + 3
    while index < len(value):
        character = value[index]
        if value.startswith("$(", index):
            if value.startswith("$((", index):
                index += 1
                continue
            return None
        if character in {"`", "'", '"'}:
            return None
        if character == "\\":
            if index + 1 < len(value) and value[index + 1] == "\n":
                index += 2
                continue
            return None
        if character == "(":
            depth += 1
            if depth > _SHELL_TOKEN_LIMIT:
                return None
            index += 1
            continue
        if character == ")":
            if depth:
                depth -= 1
                index += 1
                continue
            if index + 1 < len(value) and value[index + 1] == ")":
                return index + 2
            return None
        index += 1
    return None


def _extract_shell_parenthesized_construct(
    value: str,
    start: int,
    opening: str,
) -> tuple[str, int] | None:
    """Return one balanced shell ``X(...)`` body and its exclusive end."""

    if len(opening) != 2 or not value.startswith(opening, start):
        return None
    quote: str | None = None
    prior_quotes: list[str | None] = []
    prior_word_starts: list[bool] = []
    at_word_start = True
    pending_heredocs: list[tuple[str, bool]] = []
    depth = 1
    index = start + 2
    while index < len(value):
        character = value[index]
        if quote == "'":
            if character == "'":
                quote = None
            index += 1
            continue
        if quote == '"':
            if character == '"':
                quote = None
                index += 1
                continue
            if character == "\\" and index + 1 < len(value):
                index += 2
                continue
            if value.startswith("$((", index):
                arithmetic_end = _extract_arithmetic_expansion(value, index)
                if arithmetic_end is None:
                    return None
                index = arithmetic_end
                continue
            if value.startswith("$(", index):
                if len(prior_quotes) >= 64:
                    return None
                prior_quotes.append(quote)
                prior_word_starts.append(at_word_start)
                quote = None
                at_word_start = True
                depth += 1
                index += 2
                continue
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            at_word_start = False
            index += 1
            continue
        if character == "\\" and index + 1 < len(value):
            at_word_start = False
            index += 2
            continue
        if (
            value.startswith("<<", index)
            and not value.startswith("<<<", index)
        ):
            strip_tabs = value.startswith("<<-", index)
            operator_end = index + (3 if strip_tabs else 2)
            parsed_delimiter = _parse_shell_heredoc_delimiter(
                value,
                operator_end,
            )
            if parsed_delimiter is not None:
                delimiter, _quoted, index = parsed_delimiter
                pending_heredocs.append((delimiter, strip_tabs))
                at_word_start = False
                continue
        if character == "#" and at_word_start:
            newline = value.find("\n", index)
            if newline < 0:
                return None
            index = newline
            at_word_start = True
            continue
        if character == "\n":
            index += 1
            for delimiter, strip_tabs in pending_heredocs:
                while index <= len(value):
                    newline = value.find("\n", index)
                    if newline < 0:
                        line = value[index:]
                        index = len(value)
                    else:
                        line = value[index:newline]
                        index = newline + 1
                    comparable = line.lstrip("\t") if strip_tabs else line
                    if comparable == delimiter:
                        break
                    if newline < 0:
                        return None
            pending_heredocs.clear()
            at_word_start = True
            continue
        if value.startswith("$((", index):
            arithmetic_end = _extract_arithmetic_expansion(value, index)
            if arithmetic_end is None:
                return None
            index = arithmetic_end
            at_word_start = False
            continue
        if value.startswith("$(", index):
            if len(prior_quotes) >= 64:
                return None
            prior_quotes.append(quote)
            prior_word_starts.append(at_word_start)
            at_word_start = True
            depth += 1
            index += 2
            continue
        if character == "(":
            if len(prior_quotes) >= 64:
                return None
            prior_quotes.append(quote)
            prior_word_starts.append(at_word_start)
            at_word_start = True
            depth += 1
            index += 1
            continue
        if character == ")":
            depth -= 1
            if depth == 0:
                return value[start + len(opening) : index], index + 1
            quote = prior_quotes.pop()
            at_word_start = prior_word_starts.pop()
            index += 1
            continue
        if character.isspace() or character in ";&|<>":
            at_word_start = True
        else:
            at_word_start = False
        index += 1
    return None


def _extract_dollar_command_substitution(
    value: str,
    start: int,
) -> tuple[str, int] | None:
    return _extract_shell_parenthesized_construct(value, start, "$(")


def _extract_process_substitution(
    value: str,
    start: int,
) -> tuple[str, int] | None:
    for opening in ("<(", ">("):
        if value.startswith(opening, start):
            return _extract_shell_parenthesized_construct(
                value,
                start,
                opening,
            )
    return None


def _heredoc_expansion_tokens(
    value: str,
    *,
    maximum_tokens: int,
) -> tuple[_ShellToken, ...]:
    tokens: list[_ShellToken] = []

    def append(token: _ShellToken) -> None:
        _append_shell_token(
            tokens,
            token,
            limit=maximum_tokens,
        )

    index = 0
    while index < len(value):
        if value[index] == "\\" and index + 1 < len(value):
            index += 2
            continue
        if value[index] == "`":
            append(
                _ShellToken(
                    _SHELL_AMBIGUOUS_EXPANSION,
                    operator=True,
                )
            )
            index += 1
            continue
        if value.startswith("$((", index):
            arithmetic_end = _extract_arithmetic_expansion(value, index)
            if arithmetic_end is None:
                append(
                    _ShellToken(
                        _SHELL_AMBIGUOUS_EXPANSION,
                        operator=True,
                    )
                )
                index += 3
                continue
            index = arithmetic_end
            continue
        if value.startswith("$(", index):
            extracted = _extract_dollar_command_substitution(value, index)
            if extracted is None:
                append(
                    _ShellToken(
                        _SHELL_AMBIGUOUS_EXPANSION,
                        operator=True,
                    )
                )
                index += 2
                continue
            nested_script, index = extracted
            append(
                _ShellToken(
                    _SHELL_COMMAND_SUBSTITUTION,
                    operator=True,
                    nested_script=nested_script,
                )
            )
            continue
        index += 1
    return tuple(tokens)


def _shell_tokens(script: str) -> tuple[_ShellToken, ...]:
    """Lex enough POSIX shell syntax to classify explicit job starts.

    This deliberately does not interpret or execute the script.  Quote
    removal is limited to token classification, and here-document bodies are
    skipped so data containing shell punctuation is never treated as code.
    It is an explicit-start policy, not a proof about arbitrary dynamic code.
    """

    tokens: list[_ShellToken] = []
    current: list[str] = []
    current_quoted = False
    token_started = False
    quote: str | None = None
    index = 0
    line_start = 0

    def append(token: _ShellToken) -> None:
        _append_shell_token(tokens, token)

    def flush() -> None:
        nonlocal current_quoted, token_started
        if token_started:
            append(
                _ShellToken(
                    "".join(current),
                    quoted=current_quoted,
                )
            )
            current.clear()
            current_quoted = False
            token_started = False

    operators = (
        "&>>",
        "<<-",
        "<<<",
        "&>",
        "&&",
        "||",
        ";;",
        "<<",
        ">>",
        "<&",
        ">&",
        "<>",
        ">|",
    )
    while index < len(script):
        character = script[index]
        if quote == "'":
            if character == "'":
                quote = None
            else:
                current.append(character)
            index += 1
            continue
        if quote == '"':
            if character == '"':
                quote = None
                index += 1
                continue
            if character == "\\" and index + 1 < len(script):
                following = script[index + 1]
                if following == "\n":
                    index += 2
                    continue
                if following in _SHELL_DOUBLE_QUOTE_ESCAPES:
                    current.append(following)
                else:
                    current.extend(("\\", following))
                current_quoted = True
                index += 2
                continue
            if character == "`":
                append(
                    _ShellToken(
                        _SHELL_AMBIGUOUS_EXPANSION,
                        operator=True,
                    )
                )
                current.append(character)
                index += 1
                current_quoted = True
                continue
            if script.startswith("$((", index):
                arithmetic_end = _extract_arithmetic_expansion(script, index)
                if arithmetic_end is None:
                    append(
                        _ShellToken(
                            _SHELL_AMBIGUOUS_EXPANSION,
                            operator=True,
                        )
                    )
                    current.append("$((")
                    index += 3
                else:
                    current.append(script[index:arithmetic_end])
                    index = arithmetic_end
                current_quoted = True
                continue
            if script.startswith("$(", index):
                extracted = _extract_dollar_command_substitution(
                    script,
                    index,
                )
                if extracted is None:
                    append(
                        _ShellToken(
                            _SHELL_AMBIGUOUS_EXPANSION,
                            operator=True,
                        )
                    )
                    current.append("$(")
                    index += 2
                else:
                    nested_script, end = extracted
                    append(
                        _ShellToken(
                            _SHELL_COMMAND_SUBSTITUTION,
                            operator=True,
                            nested_script=nested_script,
                        )
                    )
                    current.append(script[index:end])
                    index = end
                current_quoted = True
                continue
            current.append(character)
            current_quoted = True
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            current_quoted = True
            token_started = True
            index += 1
            continue
        if character == "\\" and index + 1 < len(script):
            following = script[index + 1]
            if following == "\n":
                index += 2
                continue
            current.append(following)
            current_quoted = True
            token_started = True
            index += 2
            continue
        if character == "#" and not token_started:
            newline = script.find("\n", index)
            if newline < 0:
                index = len(script)
                break
            index = newline
            continue
        if character == "\n":
            flush()
            line_tokens = tokens[line_start:]
            append(_ShellToken("\n", operator=True))
            index += 1
            for (
                delimiter,
                strip_tabs,
                delimiter_quoted,
            ) in _shell_heredoc_delimiters(
                line_tokens
            ):
                while index <= len(script):
                    newline = script.find("\n", index)
                    if newline < 0:
                        line = script[index:]
                        index = len(script)
                    else:
                        line = script[index:newline]
                        index = newline + 1
                    comparable = line.lstrip("\t") if strip_tabs else line
                    if comparable == delimiter:
                        break
                    if not delimiter_quoted:
                        for expansion_token in _heredoc_expansion_tokens(
                            line,
                            maximum_tokens=(
                                _SHELL_TOKEN_LIMIT - len(tokens)
                            ),
                        ):
                            append(expansion_token)
                    if newline < 0:
                        break
            line_start = len(tokens)
            continue
        if character.isspace():
            flush()
            index += 1
            continue
        if character == "`":
            append(
                _ShellToken(
                    _SHELL_AMBIGUOUS_EXPANSION,
                    operator=True,
                )
            )
            current.append(character)
            token_started = True
            index += 1
            continue
        if script.startswith(("<(", ">("), index):
            extracted = _extract_process_substitution(script, index)
            if extracted is None:
                append(
                    _ShellToken(
                        _SHELL_AMBIGUOUS_EXPANSION,
                        operator=True,
                    )
                )
                current.append(script[index : index + 2])
                token_started = True
                index += 2
            else:
                _nested_script, end = extracted
                append(
                    _ShellToken(
                        _SHELL_PROCESS_SUBSTITUTION,
                        operator=True,
                    )
                )
                current.append(script[index:end])
                token_started = True
                index = end
            continue
        if script.startswith("$((", index):
            arithmetic_end = _extract_arithmetic_expansion(script, index)
            if arithmetic_end is None:
                append(
                    _ShellToken(
                        _SHELL_AMBIGUOUS_EXPANSION,
                        operator=True,
                    )
                )
                current.append("$((")
                token_started = True
                index += 3
            else:
                current.append(script[index:arithmetic_end])
                token_started = True
                index = arithmetic_end
            continue
        if script.startswith("$(", index):
            extracted = _extract_dollar_command_substitution(script, index)
            if extracted is None:
                append(
                    _ShellToken(
                        _SHELL_AMBIGUOUS_EXPANSION,
                        operator=True,
                    )
                )
                current.append("$(")
                token_started = True
                index += 2
            else:
                nested_script, end = extracted
                append(
                    _ShellToken(
                        _SHELL_COMMAND_SUBSTITUTION,
                        operator=True,
                        nested_script=nested_script,
                    )
                )
                current.append(script[index:end])
                token_started = True
                index = end
            continue
        matched_operator = next(
            (
                operator
                for operator in operators
                if script.startswith(operator, index)
            ),
            None,
        )
        if matched_operator is not None:
            flush()
            append(_ShellToken(matched_operator, operator=True))
            index += len(matched_operator)
            continue
        if character in ";&|()<>":
            flush()
            append(_ShellToken(character, operator=True))
            index += 1
            continue
        current.append(character)
        token_started = True
        index += 1
    flush()
    return tuple(tokens)


def _shell_command_words(
    segment: Sequence[_ShellToken],
) -> tuple[str, ...]:
    words: list[str] = []
    index = 0
    while index < len(segment):
        token = segment[index]
        if token.operator and token.value in _SHELL_REDIRECTIONS:
            index += 2
            continue
        if (
            not token.operator
            and token.value.isdigit()
            and index + 1 < len(segment)
            and segment[index + 1].operator
            and segment[index + 1].value in _SHELL_REDIRECTIONS
        ):
            index += 3
            continue
        if not token.operator:
            words.append(token.value)
        index += 1
    while words and (
        _SHELL_ASSIGNMENT.match(words[0])
        or words[0] in {"!", "{", "}"}
        or words[0] in _SHELL_RESERVED_COMMAND_PREFIXES
    ):
        words.pop(0)
    return tuple(words)


def _unwrap_command_builtin_dispatch(
    words: Sequence[str],
) -> tuple[str, ...]:
    index = 1
    while index < len(words):
        argument = words[index]
        if argument == "--":
            return tuple(words[index + 1 :])
        if not argument.startswith("-") or argument == "-":
            break
        options = argument[1:]
        if not options or any(option not in {"p", "v", "V"} for option in options):
            raise BackgroundJobUnsupported(
                "command builtin option cannot be proven foreground: "
                f"{argument}"
            )
        if "v" in options or "V" in options:
            return ()
        index += 1
    return tuple(words[index:])


def _unwrap_builtin_dispatch(
    words: Sequence[str],
) -> tuple[str, ...]:
    if len(words) <= 1:
        return ()
    if words[1] == "--":
        return tuple(words[2:])
    if words[1].startswith("-"):
        raise BackgroundJobUnsupported(
            "builtin wrapper option cannot be proven foreground: "
            f"{words[1]}"
        )
    return tuple(words[1:])


def _unwrap_exec_dispatch(
    words: Sequence[str],
) -> tuple[str, ...]:
    index = 1
    while index < len(words):
        argument = words[index]
        if argument == "--":
            return tuple(words[index + 1 :])
        if not argument.startswith("-") or argument == "-":
            break
        if argument == "-a":
            if index + 1 >= len(words):
                raise BackgroundJobUnsupported(
                    "exec -a is missing its argv0 argument"
                )
            index += 2
            continue
        options = argument[1:]
        if options and all(option in {"c", "l"} for option in options):
            index += 1
            continue
        raise BackgroundJobUnsupported(
            "exec builtin option cannot be proven foreground: "
            f"{argument}"
        )
    return tuple(words[index:])


def _unwrap_time_dispatch(
    words: Sequence[str],
) -> tuple[str, ...]:
    index = 1
    while index < len(words):
        argument = words[index]
        if argument == "--":
            return tuple(words[index + 1 :])
        if argument == "-p":
            index += 1
            continue
        if argument.startswith("-"):
            raise BackgroundJobUnsupported(
                "time option cannot be proven foreground: "
                f"{argument}"
            )
        break
    return tuple(words[index:])


def _unwrap_env_dispatch(
    words: Sequence[str],
) -> tuple[str, ...]:
    index = 1
    parsing_options = True
    while index < len(words):
        argument = words[index]
        if parsing_options:
            if argument == "--":
                parsing_options = False
                index += 1
                continue
            if argument in {"-S", "--split-string"} or argument.startswith(
                ("-S", "--split-string=")
            ):
                raise BackgroundJobUnsupported(
                    "env split-string dispatch cannot be proven foreground"
                )
            if argument in _ENV_OPTIONS_WITHOUT_ARGUMENT:
                index += 1
                continue
            if argument in _ENV_OPTIONS_WITH_ARGUMENT:
                if index + 1 >= len(words):
                    raise BackgroundJobUnsupported(
                        "env wrapper option is missing its argument"
                    )
                index += 2
                continue
            if argument.startswith(_ENV_ATTACHED_OPTION_PREFIXES):
                index += 1
                continue
            if (
                argument.startswith(("-C", "-u"))
                and len(argument) > 2
            ):
                index += 1
                continue
            if argument.startswith("-"):
                raise BackgroundJobUnsupported(
                    "env wrapper option cannot be proven foreground: "
                    f"{argument}"
                )
            parsing_options = False
        if _SHELL_ASSIGNMENT.match(argument):
            index += 1
            continue
        break
    return tuple(words[index:])


def _normalize_effective_command(
    words: Sequence[str],
    *,
    shell_builtin_context: bool = False,
) -> tuple[str, ...]:
    """Expose the executable behind bounded literal dispatcher layers."""

    normalized = tuple(words)
    wrapper_layers = 0
    while normalized:
        executable = Path(normalized[0]).name
        if executable == "busybox":
            if len(normalized) == 1 or normalized[1].startswith("-"):
                return normalized
            next_words = normalized[1:]
            shell_builtin_context = False
        elif executable == "env":
            next_words = _unwrap_env_dispatch(normalized)
            shell_builtin_context = False
        elif executable == "time":
            next_words = _unwrap_time_dispatch(normalized)
        elif shell_builtin_context and executable == "command":
            next_words = _unwrap_command_builtin_dispatch(normalized)
        elif shell_builtin_context and executable == "builtin":
            next_words = _unwrap_builtin_dispatch(normalized)
        elif shell_builtin_context and executable == "exec":
            next_words = _unwrap_exec_dispatch(normalized)
        else:
            return normalized
        wrapper_layers += 1
        if wrapper_layers > _SHELL_NESTING_LIMIT:
            raise BackgroundJobUnsupported(
                "command wrapper chain exceeds the foreground policy limit"
            )
        normalized = next_words
    return ()


def _ensure_foreground_shell_script(
    script: str,
    *,
    nesting: int = 0,
) -> None:
    if nesting > _SHELL_NESTING_LIMIT:
        raise BackgroundJobUnsupported(
            "nested shell command exceeds the foreground policy limit"
        )
    tokens = _shell_tokens(script)
    if any(
        token.operator and token.value == _SHELL_AMBIGUOUS_EXPANSION
        for token in tokens
    ):
        raise BackgroundJobUnsupported(
            "shell command contains a dynamic command expansion that cannot "
            "be proven foreground"
        )
    if any(
        token.operator and token.value == _SHELL_PROCESS_SUBSTITUTION
        for token in tokens
    ):
        raise BackgroundJobUnsupported(
            "shell command requests unsupported asynchronous process "
            "substitution"
        )
    for token in tokens:
        if token.nested_script is not None:
            _ensure_foreground_shell_script(
                token.nested_script,
                nesting=nesting + 1,
            )
    if any(token.operator and token.value == "&" for token in tokens):
        raise BackgroundJobUnsupported(
            "shell command requests an unsupported detached/background job"
        )
    segment: list[_ShellToken] = []
    segments: list[tuple[_ShellToken, ...]] = []
    for token in tokens:
        if token.operator and token.value in _SHELL_COMMAND_BOUNDARIES:
            if segment:
                segments.append(tuple(segment))
                segment.clear()
            continue
        segment.append(token)
    if segment:
        segments.append(tuple(segment))

    for command_segment in segments:
        words = _normalize_effective_command(
            _shell_command_words(command_segment),
            shell_builtin_context=True,
        )
        if not words:
            continue
        executable = Path(words[0]).name
        if executable in _BACKGROUND_STARTERS:
            raise BackgroundJobUnsupported(
                "shell command requests an unsupported detached/background "
                f"job: {executable}"
            )
        if executable in _SHELL_ENTRYPOINTS:
            nested_script: str | None = None
            for option_index, argument in enumerate(words[1:-1], start=1):
                if (
                    argument == "-c"
                    or (
                        argument.startswith("-")
                        and not argument.startswith("--")
                        and "c" in argument[1:]
                    )
                ):
                    nested_script = words[option_index + 1]
                    break
            if nested_script is not None:
                _ensure_foreground_shell_script(
                    nested_script,
                    nesting=nesting + 1,
                )
        elif executable == "eval" and len(words) > 1:
            _ensure_foreground_shell_script(
                " ".join(words[1:]),
                nesting=nesting + 1,
            )


def ensure_foreground_command(argv: Sequence[str]) -> None:
    """Reject explicit detach/background entrypoints.

    ``ctfwrap`` supervises ordinary foreground descendants.  CTF-OS does not
    yet have a supervisor that can keep a host resource lease for the complete
    lifetime of a deliberately detached job, so those starts fail closed.
    Existing job query/log/cancel utilities remain valid foreground commands.
    Shell inspection is lexical and recursive for literal scripts; runtime
    containment and descendant cleanup remain ``ctfwrap`` responsibilities.
    """

    if not argv:
        raise ValueError("command cannot be empty")
    normalized_argv = _normalize_effective_command(argv)
    if not normalized_argv:
        return
    executable = Path(normalized_argv[0]).name
    if executable in _BACKGROUND_STARTERS:
        raise BackgroundJobUnsupported(
            f"background job start is disabled without a lease supervisor: "
            f"{executable}"
        )
    if executable not in _SHELL_ENTRYPOINTS:
        return

    script: str | None = None
    for index, argument in enumerate(normalized_argv[:-1]):
        if (
            argument == "-c"
            or (
                argument.startswith("-")
                and not argument.startswith("--")
                and "c" in argument[1:]
            )
        ):
            script = normalized_argv[index + 1]
            break
    if script is None:
        return
    _ensure_foreground_shell_script(script)


def _validate_scope_component(value: str, label: str) -> None:
    """Match the literal-directory identity rules used by ``StateStore``."""

    if not isinstance(value, str):
        raise ScopeError(f"{label} must be a string")
    if not value or not value.strip():
        raise ScopeError(f"{label} cannot be empty")
    if value in {".", ".."}:
        raise ScopeError(f"{label} cannot be '.' or '..'")
    if "/" in value or "\\" in value or "\x00" in value:
        raise ScopeError(f"{label} cannot contain a path separator or NUL")
    if Path(value).is_absolute() or PureWindowsPath(value).is_absolute():
        raise ScopeError(f"{label} cannot be an absolute path")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise ScopeError(f"{label} cannot contain control characters")


@dataclass(frozen=True, slots=True)
class ChallengeScope:
    """A fixed challenge/workspace mapping.

    Paths are canonicalized once.  Individual API calls never accept mount
    paths, which prevents a caller from substituting another challenge.
    """

    challenge_id: str
    challenge_dir: Path
    work_dir: Path
    contest_id: str = "default"
    category: str = "misc"
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        for label, value in (
            ("contest_id", self.contest_id),
            ("category", self.category),
            ("challenge_id", self.challenge_id),
        ):
            _validate_scope_component(value, label)

        challenge = self.challenge_dir.expanduser().resolve(strict=True)
        if not challenge.is_dir():
            raise ScopeError(f"challenge path is not a directory: {challenge}")
        work = self.work_dir.expanduser().resolve()
        work.mkdir(parents=True, exist_ok=True)
        if not work.is_dir():
            raise ScopeError(f"work path is not a directory: {work}")
        if (
            challenge == work
            or challenge in work.parents
            or work in challenge.parents
        ):
            raise ScopeError("challenge and work paths must not overlap")
        object.__setattr__(self, "challenge_dir", challenge)
        object.__setattr__(self, "work_dir", work)
        identity = json.dumps(
            {
                "contest_id": self.contest_id,
                "category": self.category,
                "challenge_id": self.challenge_id,
                "challenge_dir": str(challenge),
                "work_dir": str(work),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        object.__setattr__(
            self,
            "fingerprint",
            hashlib.sha256(identity).hexdigest(),
        )

    @classmethod
    def create(
        cls,
        *,
        contest_id: str,
        category: str,
        challenge_id: str,
        challenge_dir: Path,
        work_dir: Path,
    ) -> ChallengeScope:
        """Construct a scope with the full identity spelled out."""

        return cls(
            challenge_id=challenge_id,
            challenge_dir=challenge_dir,
            work_dir=work_dir,
            contest_id=contest_id,
            category=category,
        )

    @property
    def qualified_id(self) -> str:
        return f"{self.contest_id}/{self.category}/{self.challenge_id}"


@dataclass(frozen=True, slots=True)
class NetworkTarget:
    host: str
    port: int | None = None
    scheme: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.host, str):
            raise ValueError("network target host must be a string")
        host = self.host.strip().lower().rstrip(".")
        if (
            not host
            or len(host) > 253
            or any(character in host for character in "/\\\x00 \t\r\n")
        ):
            raise ValueError(f"invalid network target host: {self.host!r}")
        try:
            host = ipaddress.ip_address(host).compressed
        except ValueError:
            labels = host.split(".")
            if any(
                not label
                or len(label) > 63
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                for label in labels
            ):
                raise ValueError(f"invalid network target host: {self.host!r}")
        if self.port is not None and (
            isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not 1 <= self.port <= 65535
        ):
            raise ValueError("network target port must be between 1 and 65535")
        scheme = self.scheme.lower() if self.scheme is not None else None
        if scheme is not None and not re.fullmatch(r"[a-z][a-z0-9+.-]{0,31}", scheme):
            raise ValueError(f"invalid network target scheme: {self.scheme!r}")
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "scheme", scheme)

    @classmethod
    def parse(cls, value: str) -> NetworkTarget:
        """Parse ``host``, ``host:port``, or ``scheme://host:port``."""

        from urllib.parse import urlsplit

        if "://" in value:
            parsed = urlsplit(value)
            if (
                not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in ("", "/")
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(f"invalid network target: {value!r}")
            try:
                port = parsed.port
            except ValueError as error:
                raise ValueError(f"invalid network target: {value!r}") from error
            return cls(parsed.hostname, port, parsed.scheme)
        if value.startswith("["):
            parsed = urlsplit(f"target://{value}")
            try:
                port = parsed.port
            except ValueError as error:
                raise ValueError(f"invalid network target: {value!r}") from error
            if not parsed.hostname:
                raise ValueError(f"invalid network target: {value!r}")
            return cls(parsed.hostname, port)
        if value.count(":") == 1:
            host, possible_port = value.rsplit(":", 1)
            if possible_port.isdigit():
                return cls(host, int(possible_port))
        return cls(value)

    def matches(self, requested: NetworkTarget) -> bool:
        return (
            self.host == requested.host
            and (self.port is None or self.port == requested.port)
            and (self.scheme is None or self.scheme == requested.scheme)
        )

    def as_text(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        value = f"{host}:{self.port}" if self.port is not None else host
        return f"{self.scheme}://{value}" if self.scheme else value


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    """Fail-closed network selection for a challenge container.

    Docker's built-in bridge cannot enforce a destination allowlist.  This
    contract therefore requires both a declared target and an explicit
    allowlist before selecting the configured network.  Deployments requiring
    adversarial destination enforcement should set ``enforcement`` to
    ``"proxy"`` and provide a separately restricted Docker network/proxy.
    """

    allow_targets: tuple[NetworkTarget, ...] = ()
    docker_network: str = "none"
    enforcement: str = "deny"

    def __post_init__(self) -> None:
        if self.enforcement not in {"deny", "declared", "proxy"}:
            raise ValueError("network enforcement must be deny, declared, or proxy")
        if self.allow_targets:
            if self.docker_network == "none":
                raise ValueError("an allowlist requires an explicit Docker network")
            if self.enforcement == "deny":
                raise ValueError("an allowlist requires declared or proxy enforcement")
            if self.enforcement == "proxy" and self.docker_network in {
                "bridge",
                "default",
                "host",
            }:
                raise ValueError(
                    "proxy enforcement requires a dedicated restricted "
                    "Docker network"
                )
        elif self.docker_network != "none":
            raise ValueError("network without an allowlist is not permitted")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", self.docker_network):
            raise ValueError(f"invalid Docker network: {self.docker_network!r}")

    @classmethod
    def deny_all(cls) -> NetworkPolicy:
        return cls()

    @classmethod
    def allow(
        cls,
        targets: Sequence[NetworkTarget | str],
        *,
        docker_network: str,
        enforcement: str = "declared",
    ) -> NetworkPolicy:
        parsed = tuple(
            target if isinstance(target, NetworkTarget) else NetworkTarget.parse(target)
            for target in targets
        )
        if not parsed:
            raise ValueError("at least one network target is required")
        return cls(parsed, docker_network, enforcement)

    def authorize(self, target: NetworkTarget | None) -> str:
        if target is None:
            return "none"
        if not any(allowed.matches(target) for allowed in self.allow_targets):
            raise NetworkDenied(f"network target is not allowed: {target.as_text()}")
        if self.enforcement != "proxy":
            raise NetworkDenied(
                "declared target metadata is not an egress boundary; configure "
                "an externally restricted proxy Docker network and select "
                "enforcement=proxy"
            )
        return self.docker_network


@dataclass(frozen=True, slots=True)
class CommandSpec:
    argv: tuple[str, ...]
    timeout_seconds: int = 300
    summary_bytes: int = 4096
    environment: Mapping[str, str] = field(default_factory=dict)
    network_target: NetworkTarget | None = None
    resource_request: ResourceVector = field(
        default_factory=lambda: ResourceVector(cpu=1, memory_mib=2 * 1024)
    )
    deadline_monotonic_seconds: float | None = None

    def __post_init__(self) -> None:
        if not self.argv or len(self.argv) > 4096:
            raise ValueError("command must contain between 1 and 4096 arguments")
        total_argument_bytes = 0
        for argument in self.argv:
            if (
                not isinstance(argument, str)
                or "\x00" in argument
                or len(argument.encode("utf-8")) > 1024 * 1024
            ):
                raise ValueError("command contains an invalid argument")
            total_argument_bytes += len(argument.encode("utf-8"))
        if total_argument_bytes > 1024 * 1024:
            raise ValueError("command arguments exceed 1 MiB")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int)
            or not 0 <= self.timeout_seconds <= 604800
        ):
            raise ValueError("timeout_seconds must be between 0 and 604800")
        object.__setattr__(
            self,
            "deadline_monotonic_seconds",
            validate_deadline_monotonic_seconds(
                self.deadline_monotonic_seconds
            ),
        )
        if (
            isinstance(self.summary_bytes, bool)
            or not isinstance(self.summary_bytes, int)
            or not 0 <= self.summary_bytes <= 65536
        ):
            raise ValueError("summary_bytes must be between 0 and 65536")
        environment = dict(self.environment)
        if len(environment) > 256:
            raise ValueError("environment cannot contain more than 256 variables")
        total_environment_bytes = 0
        for name, value in environment.items():
            if not ENV_NAME.fullmatch(name):
                raise ValueError(f"invalid environment variable name: {name!r}")
            if (
                not isinstance(value, str)
                or "\x00" in value
                or len(value.encode("utf-8")) > 64 * 1024
            ):
                raise ValueError(f"invalid environment value for {name}")
            total_environment_bytes += len(name.encode("ascii")) + len(
                value.encode("utf-8")
            )
        if total_environment_bytes > 1024 * 1024:
            raise ValueError("environment exceeds 1 MiB")
        request = self.resource_request
        if not isinstance(request, ResourceVector):
            raise ValueError("resource_request must be a ResourceVector")
        if request.cpu <= 0:
            raise ValueError("resource_request must include at least one CPU")
        if request.memory_mib < 256:
            raise ValueError(
                "resource_request must include at least 256 MiB of memory"
            )
        if request.gpu > 1 or request.kvm > 1 or request.network > 1:
            raise ValueError(
                "GPU, KVM, and network requests are single-slot resources"
            )
        if (self.network_target is not None) != bool(request.network):
            raise ValueError(
                "network resource request must match network_target presence"
            )
        object.__setattr__(self, "environment", MappingProxyType(environment))

    @classmethod
    def create(
        cls,
        argv: Sequence[str],
        **kwargs: object,
    ) -> CommandSpec:
        return cls(tuple(argv), **kwargs)


@dataclass(frozen=True, slots=True)
class SandboxResult:
    run_id: str
    status: str
    exit_code: int
    timed_out: bool
    duration_ms: int
    stdout_summary: str
    stderr_summary: str
    stdout_bytes: int
    stderr_bytes: int
    stdout_path: str
    stderr_path: str
    # ``ctfwrap`` records richer stream-capture metadata than the original
    # SandboxResult contract exposed.  Keep these fields optional so older
    # sandbox daemons and positional test doubles remain compatible while new
    # callers can distinguish a complete stream from one retained prefix.
    stdout_stored_bytes: int | None = None
    stderr_stored_bytes: int | None = None
    stdout_limit_bytes: int | None = None
    stderr_limit_bytes: int | None = None
    stdout_truncated: bool | None = None
    stderr_truncated: bool | None = None
    stdout_truncation_known: bool = False
    stderr_truncation_known: bool = False
    stdout_capture_complete: bool = False
    stderr_capture_complete: bool = False
    stdout_summary_truncated: bool = False
    stderr_summary_truncated: bool = False
    stdout_error: str | None = None
    stderr_error: str | None = None
    stream_capture_error: str | None = None
    orchestration_error: str | None = None


def sandbox_result_from_mapping(
    value: Mapping[str, object],
    *,
    stdout_path: str | None = None,
    stderr_path: str | None = None,
) -> SandboxResult:
    """Decode one backward-compatible ``ctfwrap`` result mapping.

    The required fields retain the original wire contract.  Optional capture
    metadata is strict when present: accepting strings such as ``"false"`` as
    booleans would turn an incomplete capture into apparently complete
    evidence.
    """

    def optional_int(name: str) -> int | None:
        raw = value.get(name)
        if raw is None:
            return None
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            raise ValueError(f"{name} must be a non-negative integer or null")
        return raw

    def optional_bool(
        name: str,
        *,
        default: bool = False,
        nullable: bool = False,
    ) -> bool | None:
        if name not in value:
            return None if nullable else default
        raw = value[name]
        if raw is None and nullable:
            return None
        if not isinstance(raw, bool):
            raise ValueError(f"{name} must be a boolean")
        return raw

    def optional_text(name: str) -> str | None:
        raw = value.get(name)
        if raw is None:
            return None
        if not isinstance(raw, str):
            raise ValueError(f"{name} must be a string or null")
        return raw

    selected_stdout_path = (
        stdout_path if stdout_path is not None else str(value["stdout_path"])
    )
    selected_stderr_path = (
        stderr_path if stderr_path is not None else str(value["stderr_path"])
    )
    return SandboxResult(
        run_id=str(value["run_id"]),
        status=str(value["status"]),
        exit_code=int(value["exit_code"]),
        timed_out=bool(value["timed_out"]),
        duration_ms=int(value["duration_ms"]),
        stdout_summary=str(value["stdout_summary"]),
        stderr_summary=str(value["stderr_summary"]),
        stdout_bytes=int(value["stdout_bytes"]),
        stderr_bytes=int(value["stderr_bytes"]),
        stdout_path=selected_stdout_path,
        stderr_path=selected_stderr_path,
        stdout_stored_bytes=optional_int("stdout_stored_bytes"),
        stderr_stored_bytes=optional_int("stderr_stored_bytes"),
        stdout_limit_bytes=optional_int("stdout_limit_bytes"),
        stderr_limit_bytes=optional_int("stderr_limit_bytes"),
        stdout_truncated=optional_bool(
            "stdout_truncated",
            nullable=True,
        ),
        stderr_truncated=optional_bool(
            "stderr_truncated",
            nullable=True,
        ),
        stdout_truncation_known=bool(
            optional_bool("stdout_truncation_known")
        ),
        stderr_truncation_known=bool(
            optional_bool("stderr_truncation_known")
        ),
        stdout_capture_complete=bool(
            optional_bool("stdout_capture_complete")
        ),
        stderr_capture_complete=bool(
            optional_bool("stderr_capture_complete")
        ),
        stdout_summary_truncated=bool(
            optional_bool("stdout_summary_truncated")
        ),
        stderr_summary_truncated=bool(
            optional_bool("stderr_summary_truncated")
        ),
        stdout_error=optional_text("stdout_error"),
        stderr_error=optional_text("stderr_error"),
        stream_capture_error=optional_text("stream_capture_error"),
        orchestration_error=optional_text("orchestration_error"),
    )


@dataclass(frozen=True, slots=True)
class ProofInput:
    """One immutable proof input and its destination inside clean ``/work``."""

    source_locator: str
    destination_locator: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        try:
            source = normalize_locator(self.source_locator)
            destination = normalize_locator(self.destination_locator)
        except SafeFileError as error:
            raise ValueError(str(error)) from error
        if not isinstance(self.sha256, str) or not re.fullmatch(
            r"[0-9a-fA-F]{64}", self.sha256
        ):
            raise ValueError("proof input sha256 must be a SHA-256 digest")
        if (
            isinstance(self.size_bytes, bool)
            or not isinstance(self.size_bytes, int)
            or not 0 <= self.size_bytes <= DEFAULT_SNAPSHOT_MAX_BYTES
        ):
            raise ValueError("proof input size is outside the snapshot bound")
        object.__setattr__(self, "source_locator", source)
        object.__setattr__(self, "destination_locator", destination)
        object.__setattr__(self, "sha256", self.sha256.lower())

    def as_dict(self) -> dict[str, object]:
        return {
            "source_locator": self.source_locator,
            "destination_locator": self.destination_locator,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> ProofInput:
        source_locator = value.get("source_locator")
        destination_locator = value.get("destination_locator")
        sha256 = value.get("sha256")
        size_bytes = value.get("size_bytes")
        if (
            not isinstance(source_locator, str)
            or not isinstance(destination_locator, str)
            or not isinstance(sha256, str)
            or isinstance(size_bytes, bool)
            or not isinstance(size_bytes, int)
        ):
            raise TypeError("proof input fields have invalid types")
        return cls(
            source_locator=source_locator,
            destination_locator=destination_locator,
            sha256=sha256,
            size_bytes=size_bytes,
        )


@dataclass(frozen=True, slots=True)
class JobRef:
    job_id: str
    scope_fingerprint: str
    runtime_id: str = "none"

    def __post_init__(self) -> None:
        if not JOB_ID.fullmatch(self.job_id):
            raise ValueError(f"invalid sandbox job id: {self.job_id!r}")
        if not re.fullmatch(r"[0-9a-f]{64}", self.scope_fingerprint):
            raise ValueError("invalid scope fingerprint")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.runtime_id):
            raise ValueError("invalid sandbox runtime id")


class JobState(str, Enum):
    STARTING = "starting"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    LOST = "lost"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class JobStatus:
    ref: JobRef
    status: JobState
    exit_code: int | None = None
    timed_out: bool = False
    cancelled: bool = False
    started_at: str | None = None
    finished_at: str | None = None


@dataclass(frozen=True, slots=True)
class JobLog:
    ref: JobRef
    stdout: str
    stderr: str
    stdout_bytes: int
    stderr_bytes: int
    stdout_truncated: bool
    stderr_truncated: bool


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    locator: str
    sha256: str
    size_bytes: int
    scope_fingerprint: str
