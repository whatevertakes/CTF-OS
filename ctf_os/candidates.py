"""Shared trust-boundary rules for possible flag values."""

from __future__ import annotations

import re

CANDIDATE_VALUE_MAX_CHARS = 1024
CANDIDATE_VALUE_MAX_BYTES = 4096

_BRACE_CANDIDATE = re.compile(
    r"(?P<prefix>[A-Za-z0-9_$][A-Za-z0-9_$.-]{0,63})"
    r"\{(?P<inner>[^{}\r\n]{1,512})\}"
)
_CODE_SOURCE = re.compile(
    r"(?i)(?:^|[/\\:])[^/\\:\s?#]+\."
    r"(?P<extension>css|js|mjs|cjs|map)(?:$|[\s?#:])"
)
_PRINTF_ARGUMENT_SELECTOR = (
    r"(?:[1-9]\d*\$|\[[1-9]\d*\]|"
    r"\([A-Za-z_][A-Za-z0-9_.-]{0,63}\))"
)
_PRINTF_STAR_WIDTH = (
    r"(?:\*(?:[1-9]\d*\$)?|\[[1-9]\d*\]\*)"
)
_PRINTF_DIRECTIVE_PATTERN = (
    rf"%(?:{_PRINTF_ARGUMENT_SELECTOR})?[-+#0 ']*"
    rf"(?:\d+|{_PRINTF_STAR_WIDTH})?"
    rf"(?:\.(?:\d*|{_PRINTF_STAR_WIDTH}))?"
    r"(?:I64|I32|hh|ll|h|l|j|z|t|L)?"
    r"[diuoxXfFeEgGaAcspn%mSCvTtbcOqUwr]"
)
_PRINTF_PLACEHOLDER = re.compile(_PRINTF_DIRECTIVE_PATTERN)
_PRINTF_DIRECTIVES_ONLY = re.compile(
    rf"(?:{_PRINTF_DIRECTIVE_PATTERN})(?:[ \t]*"
    rf"(?:{_PRINTF_DIRECTIVE_PATTERN}))*"
)
_PYTHON_FORMAT_CALL = re.compile(r"[ \t]*\.format[ \t]*\(")
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
_JS_CALL_EXPRESSION = re.compile(
    r"\s*(?:await\s+|new\s+)?"
    r"[A-Za-z_$][A-Za-z0-9_$]*"
    r"(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*"
    r"\s*\([^{};\r\n]*\)\s*;?\s*"
)
_GO_EXPORTED_TYPE_NAME = re.compile(r"[A-Z][A-Za-z0-9_]{1,63}")
_GO_POSITIONAL_COMPOSITE_MEMBERS = re.compile(
    r"\s*[A-Za-z_][A-Za-z0-9_]*"
    r"(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)+\s*,?\s*"
)
_GO_ADDRESS_OF_TYPE = re.compile(
    r"&\s*(?:[a-z_][A-Za-z0-9_]*\s*\.\s*)?$"
)
_CSS_DECLARATION = re.compile(
    r"\s*(?:--)?[-A-Za-z_][A-Za-z0-9_-]*\s*:\s*\S(?:[^;]*)\s*"
)
_STRONG_FLAG_PREFIX_SHAPE = re.compile(
    r"(?:[A-Z][A-Z0-9_]{1,31}|[A-Za-z0-9_]*(?i:ctf|flag)[A-Za-z0-9_]*)"
)
_ESCAPED_BYTE_TOKEN = re.compile(r"\\+x[0-9a-fA-F]{2}")
_JSON_KEY_SUFFIX = re.compile(r'\\*"\s*:')
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


def looks_like_printf_template_candidate(value: object) -> bool:
    """Return whether a brace candidate body is only printf directives.

    This deliberately does not reject a percent sign mixed with substantive
    text.  It targets static source spellings such as ``ctf{%s}`` and
    ``ctf{%1$02x%2$02x}``, including dynamic width/precision forms, before
    an automatic scan enters a detector's seen set or consumes its candidate
    quota. Explicitly reported candidates deliberately bypass this heuristic.
    """

    if not isinstance(value, str):
        return False
    parsed = _BRACE_CANDIDATE.fullmatch(value)
    if parsed is None:
        return False
    return (
        _PRINTF_DIRECTIVES_ONLY.fullmatch(
            parsed.group("inner").strip()
        )
        is not None
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


def _encoded_quote_delimiter_end(
    context: str,
    *,
    quote_position: int,
    quote: str,
    encoded_backslashes: int,
    quote_count: int,
) -> int | None:
    """Return the end of one encoded single/triple quote delimiter."""

    cursor = quote_position
    for ordinal in range(quote_count):
        if ordinal:
            escape_end = cursor + encoded_backslashes
            if (
                escape_end > len(context)
                or context[cursor:escape_end]
                != "\\" * encoded_backslashes
            ):
                return None
            cursor = escape_end
        if cursor >= len(context) or context[cursor] != quote:
            return None
        backslashes = 0
        probe = cursor - 1
        while probe >= 0 and context[probe] == "\\":
            backslashes += 1
            probe -= 1
        if backslashes != encoded_backslashes:
            return None
        cursor += 1
    return cursor


def _python_quote_delimiter_length(
    context: str,
    *,
    quote_position: int,
    quote: str,
    encoded_backslashes: int,
) -> int:
    """Return three for an encoded Python triple quote, otherwise one."""

    return (
        3
        if _encoded_quote_delimiter_end(
            context,
            quote_position=quote_position,
            quote=quote,
            encoded_backslashes=encoded_backslashes,
            quote_count=3,
        )
        is not None
        else 1
    )


def _is_complete_python_fstring_template(
    value: str,
    *,
    context: str,
    position: int,
) -> bool:
    """Return whether the match is contained in a bounded f-string.

    A generic flag regex sees ``f'FF{code:02X}'`` as a candidate even though
    the braces are executable Python interpolation syntax and the matched
    spelling can never be emitted by that expression. Provider events may
    contain a JSON-encoded copy of the source (``f\"FF{code:02X}\"``), and a
    match can be only the first field of a multi-field f-string. Recognize the
    exact encoded quote layer and require a bounded matching close. Explicit
    structured candidates do not call this heuristic.
    """

    match_end = position + len(value)
    lower_bound = max(0, position - 4096)
    quote_position = position - 1
    while quote_position >= lower_bound:
        quote = context[quote_position]
        if quote not in "\"'":
            quote_position -= 1
            continue
        encoded_backslashes = 0
        cursor = quote_position - 1
        while cursor >= 0 and context[cursor] == "\\":
            encoded_backslashes += 1
            cursor -= 1
        prefix_end = quote_position - encoded_backslashes
        prefix_start = prefix_end
        while (
            prefix_start > 0
            and prefix_end - prefix_start < 2
            and context[prefix_start - 1].isalpha()
        ):
            prefix_start -= 1
        prefix = context[prefix_start:prefix_end].casefold()
        if prefix not in {"f", "fr", "rf"} or (
            prefix_start != 0
            and (
                context[prefix_start - 1].isalnum()
                or context[prefix_start - 1] == "_"
            )
        ):
            quote_position -= 1
            continue

        quote_count = _python_quote_delimiter_length(
            context,
            quote_position=quote_position,
            quote=quote,
            encoded_backslashes=encoded_backslashes,
        )
        content_start = _encoded_quote_delimiter_end(
            context,
            quote_position=quote_position,
            quote=quote,
            encoded_backslashes=encoded_backslashes,
            quote_count=quote_count,
        )
        if content_start is None:
            quote_position -= 1
            continue

        # This opening delimiter must still contain the match. Same-layer
        # quotes inside a serialized event close it; differently escaped
        # quotes belong to an inner representation.
        probe_position = content_start
        closed_before_candidate = False
        while probe_position < position:
            if context[probe_position] != quote:
                probe_position += 1
                continue
            backslashes = 0
            probe = probe_position - 1
            while probe >= 0 and context[probe] == "\\":
                backslashes += 1
                probe -= 1
            if backslashes == encoded_backslashes:
                close_end = _encoded_quote_delimiter_end(
                    context,
                    quote_position=probe_position,
                    quote=quote,
                    encoded_backslashes=encoded_backslashes,
                    quote_count=quote_count,
                )
                if close_end is not None:
                    closed_before_candidate = True
                    break
            probe_position += 1
        if closed_before_candidate:
            quote_position -= 1
            continue

        search_end = min(len(context), match_end + 2048)
        cursor = match_end
        while cursor < search_end:
            if quote_count == 1 and context[cursor] in "\r\n":
                break
            if context[cursor] != quote:
                cursor += 1
                continue
            backslashes = 0
            probe = cursor - 1
            while probe >= 0 and context[probe] == "\\":
                backslashes += 1
                probe -= 1
            if backslashes == encoded_backslashes:
                close_end = _encoded_quote_delimiter_end(
                    context,
                    quote_position=cursor,
                    quote=quote,
                    encoded_backslashes=encoded_backslashes,
                    quote_count=quote_count,
                )
                if close_end is not None:
                    return True
            cursor += 1
        quote_position -= 1
    return False


def _has_bounded_python_call_close(
    context: str,
    *,
    opening_parenthesis: int,
) -> bool:
    """Return whether a method call closes within the scanner's local view."""

    depth = 0
    search_end = min(len(context), opening_parenthesis + 2048)
    for character in context[opening_parenthesis:search_end]:
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return True
            if depth < 0:
                return False
    return False


def _is_complete_python_format_template(
    value: str,
    *,
    context: str,
    position: int,
) -> bool:
    """Return whether the match belongs to a bounded ``str.format`` call.

    Python format fields such as ``0x{:x}`` resemble permissive flag
    patterns, but a quoted template immediately invoked with ``.format(...)``
    is source code rather than emitted output. Match the exact quote escape
    layer so the same rule works on JSON-encoded provider events. Merely
    quoted values and ``.format`` attribute references remain candidates.
    """

    match_end = position + len(value)
    lower_bound = max(0, position - 4096)
    quote_position = position - 1
    while quote_position >= lower_bound:
        quote = context[quote_position]
        if quote not in "\"'":
            quote_position -= 1
            continue
        encoded_backslashes = 0
        cursor = quote_position - 1
        while cursor >= 0 and context[cursor] == "\\":
            encoded_backslashes += 1
            cursor -= 1
        quote_count = _python_quote_delimiter_length(
            context,
            quote_position=quote_position,
            quote=quote,
            encoded_backslashes=encoded_backslashes,
        )
        content_start = _encoded_quote_delimiter_end(
            context,
            quote_position=quote_position,
            quote=quote,
            encoded_backslashes=encoded_backslashes,
            quote_count=quote_count,
        )
        if content_start is None:
            quote_position -= 1
            continue

        # The candidate must still be inside this exact literal. An escaped
        # same-character quote has a different backslash count and is content.
        probe_position = content_start
        closed_before_match_end = False
        while probe_position < match_end:
            if context[probe_position] != quote:
                probe_position += 1
                continue
            backslashes = 0
            probe = probe_position - 1
            while probe >= 0 and context[probe] == "\\":
                backslashes += 1
                probe -= 1
            if backslashes == encoded_backslashes:
                close_end = _encoded_quote_delimiter_end(
                    context,
                    quote_position=probe_position,
                    quote=quote,
                    encoded_backslashes=encoded_backslashes,
                    quote_count=quote_count,
                )
                if close_end is not None:
                    closed_before_match_end = True
                    break
            probe_position += 1
        if closed_before_match_end:
            quote_position -= 1
            continue

        search_end = min(len(context), match_end + 2048)
        cursor = match_end
        while cursor < search_end:
            if quote_count == 1 and context[cursor] in "\r\n":
                break
            if context[cursor] != quote:
                cursor += 1
                continue
            backslashes = 0
            probe = cursor - 1
            while probe >= 0 and context[probe] == "\\":
                backslashes += 1
                probe -= 1
            if backslashes != encoded_backslashes:
                cursor += 1
                continue
            close_end = _encoded_quote_delimiter_end(
                context,
                quote_position=cursor,
                quote=quote,
                encoded_backslashes=encoded_backslashes,
                quote_count=quote_count,
            )
            if close_end is None:
                cursor += 1
                continue
            format_call = _PYTHON_FORMAT_CALL.match(context, close_end)
            if format_call is not None and _has_bounded_python_call_close(
                context,
                opening_parenthesis=format_call.end() - 1,
            ):
                return True
            # This is the first closing delimiter for this opening quote, so
            # later same-layer quotes cannot close the same literal.
            break
        quote_position -= 1
    return False


def _encoded_json_whitespace_start(
    context: str,
    *,
    end: int,
    lower_bound: int,
) -> tuple[int, bool] | None:
    """Return one bounded JSON-encoded whitespace token before ``end``.

    Repeated JSON encoding turns a source tab/newline into one, two, four,
    then eight backslashes followed by its escape letter.  Recognize only
    those exact bounded spellings; arbitrary source backslash runs are not
    whitespace evidence.
    """

    if end <= lower_bound or context[end - 1] not in "nrt":
        return None
    escape = context[end - 1]
    cursor = end - 1
    while cursor > lower_bound and context[cursor - 1] == "\\":
        cursor -= 1
    if cursor > 0 and context[cursor - 1] == "\\":
        return None
    if end - 1 - cursor not in {1, 2, 4, 8}:
        return None
    return cursor, escape in "nr"


def _bounded_quote_leading_whitespace(
    context: str,
    *,
    end: int,
) -> tuple[int, bool, bool]:
    """Skip narrowly bounded source/JSON whitespace before a quote."""

    lower_bound = max(0, end - 256)
    cursor = end
    saw_whitespace = False
    saw_line_break = False
    while cursor > lower_bound:
        character = context[cursor - 1]
        if character in " \t":
            saw_whitespace = True
            cursor -= 1
            continue
        if character in "\r\n":
            saw_whitespace = True
            saw_line_break = True
            cursor -= 1
            continue
        encoded = _encoded_json_whitespace_start(
            context,
            end=cursor,
            lower_bound=lower_bound,
        )
        if encoded is None:
            break
        cursor, encoded_line_break = encoded
        saw_whitespace = True
        saw_line_break = saw_line_break or encoded_line_break
    return cursor, saw_whitespace, saw_line_break


def _python_keyword_boundary(
    context: str,
    *,
    keyword_start: int,
) -> bool:
    """Return whether an exact keyword starts at a source/JSON boundary."""

    if keyword_start == 0 or not (
        context[keyword_start - 1].isalnum()
        or context[keyword_start - 1] == "_"
    ):
        return True
    lower_bound = max(0, keyword_start - 9)
    encoded = _encoded_json_whitespace_start(
        context,
        end=keyword_start,
        lower_bound=lower_bound,
    )
    return encoded is not None


def _quoted_literal_opening_signal(
    context: str,
    *,
    quote_position: int,
    encoded_backslashes: int,
) -> bool:
    """Return whether a quote has a high-confidence opening context."""

    prefix_end = quote_position - encoded_backslashes
    if prefix_end == 0:
        return True
    prefix_start = prefix_end
    while (
        prefix_start > 0
        and prefix_end - prefix_start < 2
        and context[prefix_start - 1].isalpha()
    ):
        prefix_start -= 1
    prefix = context[prefix_start:prefix_end].casefold()
    if prefix in {
        "b",
        "br",
        "f",
        "fr",
        "r",
        "rb",
        "rf",
        "u",
        "ur",
        "ru",
    } and (
        prefix_start == 0
        or not (
            context[prefix_start - 1].isalnum()
            or context[prefix_start - 1] == "_"
        )
    ):
        return True
    whitespace_start, whitespace_before_quote, saw_line_break = (
        _bounded_quote_leading_whitespace(
            context,
            end=prefix_end,
        )
    )
    cursor = whitespace_start - 1
    if not saw_line_break and (
        cursor < 0 or context[cursor] in "=:+,([{;>"
    ):
        return True
    if not whitespace_before_quote:
        return False

    # A quoted literal may start directly after a Python conditional keyword,
    # including the filter clause of a comprehension and either arm of a
    # conditional expression. This remains narrow: require bounded source or
    # JSON-encoded whitespace before the quote and the complete preceding
    # identifier to be exactly ``if``, ``elif``, or ``else``. Only ``else``
    # may cross a bounded line break before the literal.
    keyword_end = cursor + 1
    for keyword in ("if", "elif", "else"):
        if saw_line_break and keyword != "else":
            continue
        keyword_start = keyword_end - len(keyword)
        if (
            keyword_start < 0
            or context[keyword_start:keyword_end] != keyword
        ):
            continue
        if _python_keyword_boundary(
            context,
            keyword_start=keyword_start,
        ):
            return True
    return False


def _crosses_quoted_literal_boundary(
    value: str,
    *,
    context: str,
    position: int,
) -> bool:
    """Recognize a brace match that escapes its containing string.

    Model events often embed structured output as a JSON string. A generic
    regex can begin at an incomplete ``flag{`` inside one JSON/Python string
    and consume the enclosing record's closing brace. Suppress only when a
    likely opening quote exists and its same encoded quote layer closes before
    the regex match ends. A real candidate wholly contained in the string is
    therefore retained.
    """

    match_end = position + len(value)
    lower_bound = max(0, position - 4096)
    quote_position = position - 1
    while quote_position >= lower_bound:
        quote = context[quote_position]
        if quote not in "\"'":
            quote_position -= 1
            continue
        encoded_backslashes = 0
        cursor = quote_position - 1
        while cursor >= 0 and context[cursor] == "\\":
            encoded_backslashes += 1
            cursor -= 1
        if not _quoted_literal_opening_signal(
            context,
            quote_position=quote_position,
            encoded_backslashes=encoded_backslashes,
        ):
            quote_position -= 1
            continue
        quote_count = _python_quote_delimiter_length(
            context,
            quote_position=quote_position,
            quote=quote,
            encoded_backslashes=encoded_backslashes,
        )
        content_start = _encoded_quote_delimiter_end(
            context,
            quote_position=quote_position,
            quote=quote,
            encoded_backslashes=encoded_backslashes,
            quote_count=quote_count,
        )
        if content_start is None:
            quote_position -= 1
            continue
        # Do not reuse an opening quote from an earlier, already closed
        # literal. The candidate must still be inside this exact encoded quote
        # layer at ``position``.
        probe_position = content_start
        closed_before_candidate = False
        while probe_position < position:
            if context[probe_position] != quote:
                probe_position += 1
                continue
            backslashes = 0
            probe = probe_position - 1
            while probe >= 0 and context[probe] == "\\":
                backslashes += 1
                probe -= 1
            if backslashes == encoded_backslashes:
                close_end = _encoded_quote_delimiter_end(
                    context,
                    quote_position=probe_position,
                    quote=quote,
                    encoded_backslashes=encoded_backslashes,
                    quote_count=quote_count,
                )
                if close_end is not None:
                    closed_before_candidate = True
                    break
            probe_position += 1
        if closed_before_candidate:
            quote_position -= 1
            continue
        cursor = position
        while cursor < match_end:
            if context[cursor] != quote:
                cursor += 1
                continue
            backslashes = 0
            probe = cursor - 1
            while probe >= 0 and context[probe] == "\\":
                backslashes += 1
                probe -= 1
            if backslashes == encoded_backslashes:
                close_end = _encoded_quote_delimiter_end(
                    context,
                    quote_position=cursor,
                    quote=quote,
                    encoded_backslashes=encoded_backslashes,
                    quote_count=quote_count,
                )
                if close_end is not None:
                    return True
            cursor += 1
        return False
    return False


def _is_complete_json_string_literal(
    value: str,
    *,
    context: str,
    position: int,
) -> bool:
    """Protect an exact JSON string value, including nested JSON escapes."""

    end = position + len(value)
    if position < 1 or context[position - 1] != '"':
        return False
    cursor = end
    while cursor < len(context) and context[cursor] == "\\":
        cursor += 1
    return cursor < len(context) and context[cursor] == '"'


def _is_go_address_of_positional_composite_literal(
    *,
    prefix: str,
    inner: str,
    context: str,
    position: int,
) -> bool:
    """Recognize a narrow, source-grounded Go composite literal shape.

    Go commonly constructs a pointer with ``&Type{first, second}``.  Static
    source locators can expose that spelling to the permissive flag regex.
    Require the address-of operator, an exported-type name, and at least two
    bare positional fields.  Quoted values and strong flag prefixes are
    protected by the caller before this heuristic is reached.
    """

    if (
        _GO_EXPORTED_TYPE_NAME.fullmatch(prefix) is None
        or _GO_POSITIONAL_COMPOSITE_MEMBERS.fullmatch(inner) is None
    ):
        return False
    leader = context[max(0, position - 128) : position]
    return _GO_ADDRESS_OF_TYPE.search(leader) is not None


def _find_json_key(text: str, key: str, *, start: int) -> int:
    """Find a quoted JSON key whose closing quote may itself be escaped."""

    position = text.find(key, start)
    while position != -1:
        suffix = text[position + len(key) : position + len(key) + 16]
        if (
            position > 0
            and text[position - 1] == '"'
            and _JSON_KEY_SUFFIX.match(suffix) is not None
        ):
            return position
        position = text.find(key, position + len(key))
    return -1


def _escaped_byte_json_diagnostic_kind(
    value: str,
    *,
    prefix: str,
    context: str,
    position: int,
) -> str | None:
    """Classify a narrowly shaped escaped-byte transform diagnostic match.

    A JSONL diagnostic such as ``{"escaped":"\\xae{...", ...}`` can make
    the generic brace regex start at the ``x`` in ``\\xae`` and use the JSON
    object's closing brace as the candidate's closing brace.  The resulting
    value is not one JSON string at all.  A shorter random byte preview can
    also contain its own closing brace.  Recognize only the local record shape
    used by these diagnostics: an x-prefixed weak match, a nearby ``\\xHH``
    byte token, and the ordered JSON keys ``printable_ratio`` and
    ``transform`` immediately following the preview.

    ``fragment`` means the regex crossed from the preview string into JSON
    metadata. ``weak_value`` is a complete random-looking brace fragment in
    the same preview record. Callers protect strong flag prefixes and exact
    JSON string values before suppressing the latter.
    """

    if not prefix.startswith("x"):
        return None

    # Keep repeated untrusted scans bounded even if a tool emits one enormous
    # line. The generic candidate itself is capped at roughly one KiB, and the
    # two diagnostic keys are adjacent to the escaped preview.
    match_end = position + len(value)
    lower_bound = max(0, position - 1024)
    prior_newline = context.rfind("\n", lower_bound, position)
    window_start = (
        prior_newline + 1 if prior_newline != -1 else lower_bound
    )
    upper_bound = min(len(context), match_end + 2048)
    next_newline = context.find("\n", match_end, upper_bound)
    window_end = (
        next_newline if next_newline != -1 else upper_bound
    )
    record = context[window_start:window_end]
    relative_start = position - window_start
    relative_end = match_end - window_start

    printable_position = _find_json_key(
        record,
        "printable_ratio",
        start=relative_start,
    )
    if (
        printable_position == -1
        or printable_position > relative_end + 256
    ):
        return None
    transform_position = _find_json_key(
        record,
        "transform",
        start=printable_position + len("printable_ratio"),
    )
    if (
        transform_position == -1
        or transform_position > relative_end + 512
    ):
        return None

    escape_window_start = max(0, relative_start - 512)
    escape_window_end = min(
        len(record),
        transform_position + len("transform") + 256,
    )
    if (
        _ESCAPED_BYTE_TOKEN.search(
            record[escape_window_start:escape_window_end]
        )
        is None
    ):
        return None

    if printable_position < relative_end:
        return "fragment"
    return "weak_value"


def looks_like_generic_code_noise(
    value: str,
    *,
    source: str,
    context: str,
    position: int,
) -> bool:
    """Recognize only high-confidence code/template false positives.

    Callers use this for untyped generic scanning. Explicit structured
    candidates bypass these context-sensitive heuristics. The narrower,
    context-free printf-directive-only check is also limited to automatic
    scan extraction.
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
    if _is_complete_python_fstring_template(
        value,
        context=context,
        position=position,
    ):
        return True
    if _is_complete_python_format_template(
        value,
        context=context,
        position=position,
    ):
        return True
    if _crosses_quoted_literal_boundary(
        value,
        context=context,
        position=position,
    ):
        return True

    escaped_diagnostic_kind = _escaped_byte_json_diagnostic_kind(
        value,
        prefix=prefix,
        context=context,
        position=position,
    )
    if escaped_diagnostic_kind == "fragment":
        return True

    # A strong but non-enumerated flag prefix is better evidence than
    # surrounding code. Unicode-escape, printf, and f-string templates were
    # already rejected above; arbitrary acronym prefixes remain visible.
    if (
        _has_strong_flag_prefix_shape(prefix)
        or _is_complete_quoted_literal(
            value,
            context=context,
            position=position,
        )
        or _is_complete_json_string_literal(
            value,
            context=context,
            position=position,
        )
    ):
        return False
    if escaped_diagnostic_kind == "weak_value":
        return True
    if _is_go_address_of_positional_composite_literal(
        prefix=prefix,
        inner=inner,
        context=context,
        position=position,
    ):
        return True

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
            or _JS_CALL_EXPRESSION.fullmatch(inner) is not None
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
    "looks_like_printf_template_candidate",
    "looks_like_generic_code_noise",
]
