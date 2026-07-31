"""Shared trust-boundary rules for possible flag values."""

from __future__ import annotations

import re

CANDIDATE_VALUE_MAX_CHARS = 1024
CANDIDATE_VALUE_MAX_BYTES = 4096

_BRACE_CANDIDATE = re.compile(
    r"(?P<prefix>[A-Za-z_$][A-Za-z0-9_$.-]{0,63})"
    r"\{(?P<inner>[^{}\r\n]{1,512})\}"
)
_CODE_SOURCE = re.compile(
    r"(?i)(?:^|[/\\:])[^/\\:\s?#]+\."
    r"(?P<extension>css|js|mjs|cjs|map)(?:$|[\s?#:])"
)
_PRINTF_PLACEHOLDER = re.compile(
    r"%(?:[-+#0 ']*\d*(?:\.\d+)?(?:hh|h|ll|l|j|z|t|L)?"
    r"[diuoxXfFeEgGaAcspn%])"
)
_JS_OBJECT_MEMBER = re.compile(
    r"""(?:^|,)\s*(?:
        [A-Za-z_$][A-Za-z0-9_$]*
        |[0-9]+
        |"[^"\\\r\n]*(?:\\.[^"\\\r\n]*)*"
        |'[^'\\\r\n]*(?:\\.[^'\\\r\n]*)*'
    )\s*:""",
    re.VERBOSE,
)
_JS_SHORTHAND_MEMBERS = re.compile(
    r"\s*[A-Za-z_$][A-Za-z0-9_$]*"
    r"(?:\s*,\s*[A-Za-z_$][A-Za-z0-9_$]*)+\s*"
)
_JS_STATEMENT_SIGNAL = re.compile(
    r"""(?:^|;)\s*(?:
        (?:const|let|var)\s+[A-Za-z_$]
        |(?:return|throw|break|continue)\b
        |[A-Za-z_$][A-Za-z0-9_$.\[\]]*\s*
          (?:=>|={1,3}|[+\-*/%&|^]=|\+\+|--)
    )""",
    re.VERBOSE,
)
_CSS_DECLARATION = re.compile(
    r"\s*(?:--)?[-A-Za-z_][A-Za-z0-9_-]*\s*:\s*\S(?:[^;]*)\s*"
)
_STRONG_FLAG_PREFIX_SHAPE = re.compile(
    r"(?:[A-Z][A-Z0-9_]{1,31}|[A-Za-z0-9_]*(?i:ctf|flag)[A-Za-z0-9_]*)"
)
_HTML_STYLE_PREFIXES = frozenset(
    {
        "a",
        "body",
        "button",
        "div",
        "form",
        "html",
        "img",
        "input",
        "label",
        "li",
        "main",
        "nav",
        "p",
        "pre",
        "section",
        "select",
        "span",
        "style",
        "table",
        "td",
        "textarea",
        "th",
        "tr",
        "ul",
    }
)
_JS_BLOCK_PREFIXES = frozenset(
    {
        "catch",
        "class",
        "else",
        "finally",
        "for",
        "function",
        "if",
        "return",
        "switch",
        "try",
        "while",
    }
)
_CSS_PSEUDO_PREFIXES = frozenset(
    {
        "active",
        "after",
        "before",
        "checked",
        "disabled",
        "enabled",
        "focus",
        "hover",
        "link",
        "root",
        "target",
        "visited",
    }
)


class FlagNotificationError(RuntimeError):
    """A detected candidate could not be durably and visibly reported."""


def flag_notification_error(error: Exception) -> FlagNotificationError:
    detail = str(error)[:1024]
    return FlagNotificationError(
        "flag candidate notification failed: "
        f"{type(error).__name__}: {detail}"
    )


def candidate_value_is_valid(value: object) -> bool:
    """Return whether a value is safe to persist as a flag candidate."""

    if not isinstance(value, str):
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return bool(
        value
        and len(value) <= CANDIDATE_VALUE_MAX_CHARS
        and len(encoded) <= CANDIDATE_VALUE_MAX_BYTES
        and all(character.isprintable() for character in value)
    )


def _markup_code_kind(text: str, position: int) -> str | None:
    """Return the nearest open ``script``/``style`` element, if visible."""

    prefix = text[:position].casefold()
    nearest: tuple[int, str] | None = None
    for tag in ("script", "style"):
        opened = prefix.rfind(f"<{tag}")
        closed = prefix.rfind(f"</{tag}")
        if opened > closed:
            boundary = opened + len(tag) + 1
            if (
                boundary < len(prefix)
                and prefix[boundary] not in " \t\r\n/>"
            ):
                continue
            terminator = prefix.find(">", boundary)
            if (
                terminator != -1
                and (nearest is None or opened > nearest[0])
            ):
                nearest = (opened, tag)
    return nearest[1] if nearest is not None else None


def _code_source_kind(source: str) -> str | None:
    match = _CODE_SOURCE.search(source)
    if match is None:
        return None
    extension = match.group("extension").casefold()
    if extension == "css":
        return "style"
    if extension == "map":
        return "map"
    return "script"


def _css_declaration_count(inner: str) -> int:
    """Count a complete, flat CSS declaration list or return zero."""

    parts = inner.split(";")
    if parts and not parts[-1].strip():
        parts.pop()
    if not parts or any(
        _CSS_DECLARATION.fullmatch(part) is None for part in parts
    ):
        return 0
    return len(parts)


def _has_css_selector_signal(context: str, position: int) -> bool:
    """Recognize the selector punctuation omitted by the generic match."""

    return position > 0 and context[position - 1] in ".#"


def _has_strong_flag_prefix_shape(prefix: str) -> bool:
    """Protect arbitrary acronym/CTF-shaped prefixes without an allowlist."""

    return _STRONG_FLAG_PREFIX_SHAPE.fullmatch(prefix) is not None


def _is_complete_quoted_literal(
    value: str,
    *,
    context: str,
    position: int,
) -> bool:
    """Return whether the exact match is visibly enclosed by one quote pair."""

    end = position + len(value)
    return (
        position > 0
        and end < len(context)
        and context[position - 1] in "\"'`"
        and context[end] == context[position - 1]
    )


def looks_like_generic_code_noise(
    value: str,
    *,
    source: str,
    context: str,
    position: int,
) -> bool:
    """Recognize only high-confidence CSS/JS/placeholder false positives.

    Callers use this for untyped generic scanning. Explicit structured
    candidates bypass it, so a flag-looking string is never silently rejected
    merely because its spelling resembles source code.
    """

    parsed = _BRACE_CANDIDATE.fullmatch(value)
    if parsed is None:
        return False
    prefix = parsed.group("prefix")
    inner = parsed.group("inner")
    folded_prefix = prefix.casefold()

    if re.fullmatch(r"u[0-9a-fA-F]{4,8}", prefix):
        return True
    if _PRINTF_PLACEHOLDER.fullmatch(inner.strip()) is not None:
        return True

    # A strong but non-enumerated flag prefix is better evidence than
    # surrounding code. Unicode-escape and printf artifacts were already
    # rejected above; arbitrary acronym prefixes remain visible.
    if _has_strong_flag_prefix_shape(prefix) or _is_complete_quoted_literal(
        value,
        context=context,
        position=position,
    ):
        return False

    source_kind = _code_source_kind(source)
    markup_kind = _markup_code_kind(context, position)
    css_declarations = _css_declaration_count(inner)
    js_members = len(_JS_OBJECT_MEMBER.findall(inner))

    if (
        css_declarations >= 1
        and (
            source_kind in {"style", "map"}
            or markup_kind == "style"
            or _has_css_selector_signal(context, position)
            or folded_prefix in _HTML_STYLE_PREFIXES
            or folded_prefix in _CSS_PSEUDO_PREFIXES
        )
    ):
        return True
    if (
        folded_prefix in _JS_BLOCK_PREFIXES
        and (
            js_members >= 1
            or _JS_SHORTHAND_MEMBERS.fullmatch(inner) is not None
            or _JS_STATEMENT_SIGNAL.search(inner) is not None
        )
    ):
        return True
    if (
        source_kind in {"script", "map"} or markup_kind == "script"
    ) and (
        js_members >= 2
        or _JS_SHORTHAND_MEMBERS.fullmatch(inner) is not None
    ):
        return True
    return False


__all__ = [
    "CANDIDATE_VALUE_MAX_BYTES",
    "CANDIDATE_VALUE_MAX_CHARS",
    "FlagNotificationError",
    "candidate_value_is_valid",
    "flag_notification_error",
    "looks_like_generic_code_noise",
]
