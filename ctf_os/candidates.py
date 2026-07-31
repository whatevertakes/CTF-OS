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
    r"(?:css|js|mjs|cjs|map)(?:$|[\s?#:])"
)
_PRINTF_PLACEHOLDER = re.compile(
    r"%(?:[-+#0 ']*\d*(?:\.\d+)?(?:hh|h|ll|l|j|z|t|L)?"
    r"[diuoxXfFeEgGaAcspn%])"
)
_JS_OBJECT_MEMBER = re.compile(
    r"(?:^|,)\s*[A-Za-z_$][A-Za-z0-9_$]*\s*:"
)
_CSS_DECLARATION = re.compile(
    r"(?:^|;)\s*[-A-Za-z][A-Za-z0-9-]*\s*:"
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


def _inside_markup_code(text: str, position: int) -> bool:
    """Return whether ``position`` is inside a visible script/style block."""

    prefix = text[:position].casefold()
    for tag in ("script", "style"):
        opened = prefix.rfind(f"<{tag}")
        closed = prefix.rfind(f"</{tag}")
        if opened > closed:
            terminator = prefix.find(">", opened)
            if terminator != -1 and terminator < position:
                return True
    return False


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

    code_source = _CODE_SOURCE.search(source) is not None
    markup_code = _inside_markup_code(context, position)
    css_declarations = len(_CSS_DECLARATION.findall(inner))
    js_members = len(_JS_OBJECT_MEMBER.findall(inner))

    if (
        css_declarations >= 2
        and (
            code_source
            or markup_code
            or folded_prefix in _HTML_STYLE_PREFIXES
        )
    ):
        return True
    if (
        js_members >= 2
        and (
            code_source
            or markup_code
            or folded_prefix in _JS_BLOCK_PREFIXES
        )
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
