"""Terminal-safe rendering for untrusted challenge-derived text."""

from __future__ import annotations

import unicodedata

_BIDI_CONTROLS = frozenset(
    {
        "\u061c",
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    }
)


def terminal_safe(value: object, *, multiline: bool = False) -> str:
    """Escape terminal controls while preserving ordinary Unicode text.

    Control and bidi-format characters are rendered as visible ``\\xNN`` or
    ``\\uNNNN`` sequences.  Newlines are retained only for already-structured
    JSON/Markdown output.
    """

    output: list[str] = []
    for character in str(value):
        codepoint = ord(character)
        if multiline and character in {"\n", "\r"}:
            output.append(character)
            continue
        if character == "\t":
            output.append(character if multiline else "\\t")
            continue
        category = unicodedata.category(character)
        if (
            character in _BIDI_CONTROLS
            or category in {"Cc", "Cf", "Cs", "Zl", "Zp"}
            or 0x7F <= codepoint <= 0x9F
        ):
            if codepoint <= 0xFF:
                output.append(f"\\x{codepoint:02x}")
            elif codepoint <= 0xFFFF:
                output.append(f"\\u{codepoint:04x}")
            else:
                output.append(f"\\U{codepoint:08x}")
            continue
        output.append(character)
    return "".join(output)


__all__ = ["terminal_safe"]
