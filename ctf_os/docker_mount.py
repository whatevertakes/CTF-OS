"""Safe construction of Docker ``--mount`` CSV specifications."""

from __future__ import annotations

import os


def _csv_field(value: str) -> str:
    """Encode one field for Docker's Go CSV ``--mount`` parser."""

    if "\x00" in value:
        raise ValueError("Docker mount fields must not contain NUL")
    if any(character in value for character in ',\"\r\n'):
        return '"' + value.replace('"', '""') + '"'
    return value


def bind_mount_spec(
    source: os.PathLike[str] | str,
    destination: str,
    *,
    readonly: bool = False,
) -> str:
    """Return one bind-mount spec without treating path commas as separators."""

    source_text = os.fspath(source)
    fields = (
        _csv_field("type=bind"),
        _csv_field(f"src={source_text}"),
        _csv_field(f"dst={destination}"),
    )
    suffix = (_csv_field("readonly"),) if readonly else ()
    return ",".join((*fields, *suffix))
