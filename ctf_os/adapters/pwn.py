from __future__ import annotations

from .base import ExperimentSpec, GenericAdapter, ProgressMarker, ProofPolicy


# Match the per-file bound admitted by the immutable runtime source snapshot.
_PWN_ADAPTER_PRIMARY_MAX_BYTES = 16 * 1024 * 1024
_PWN_ZIP_MAX_ENTRIES = 64
_PWN_ZIP_MAX_OUTPUT_BYTES = 64 * 1024

_BINARY_METADATA = (
    "set -eu; target=$1; checksec_path=${2:-/usr/bin/checksec}; "
    "if [ -L \"$target\" ]; then "
    "printf '%s\\n' 'ctfos_binary_metadata_error=symlink_source_binding' "
    ">&2; exit 2; fi; "
    "if [ ! -f \"$target\" ]; then "
    "printf '%s\\n' 'ctfos_binary_metadata_mode=skipped' "
    "'ctfos_binary_metadata_reason=no_regular_source_binding'; "
    "exit 0; fi; "
    "case \"${target##*/}\" in *.[zZ][iI][pP]) "
    "printf '%s\\n' 'ctfos_binary_metadata_mode=skipped' "
    "'ctfos_binary_metadata_reason=archive_primary_non_executable'; "
    "exit 0;; esac; "
    "if ! size=$(/usr/bin/stat --format=%s -- \"$target\"); then "
    "printf '%s\\n' 'ctfos_binary_metadata_error=source_stat_failed' "
    ">&2; exit 2; fi; "
    f"if [ \"$size\" -gt {_PWN_ADAPTER_PRIMARY_MAX_BYTES} ]; then "
    "printf '%s\\n' 'ctfos_binary_metadata_mode=skipped' "
    "'ctfos_binary_metadata_reason=source_size_limit_exceeded'; "
    "exit 0; fi; "
    "if ! octets=$(/usr/bin/od -An -N4 -tu1 -- \"$target\"); then "
    "printf '%s\\n' 'ctfos_binary_metadata_error=source_magic_read_failed' "
    ">&2; exit 2; fi; "
    "set -- $octets; "
    "if [ \"${1:-}\" != 127 ] || [ \"${2:-}\" != 69 ] || "
    "[ \"${3:-}\" != 76 ] || [ \"${4:-}\" != 70 ]; then "
    "printf '%s\\n' 'ctfos_binary_metadata_mode=skipped' "
    "'ctfos_binary_metadata_reason=unsupported_primary_format'; "
    "exit 0; fi; "
    "exec \"$checksec_path\" \"--file=$target\""
)

_RUNTIME_BASELINE = (
    "set +e; umask 077; target=$1; work_root=${2:-/work}; "
    "if [ -L \"$target\" ]; then "
    "printf '%s\\n' 'ctfos_runtime_baseline_error=symlink_source_binding' "
    ">&2; exit 2; fi; "
    "if [ ! -f \"$target\" ]; then "
    "printf '%s\\n' 'ctfos_runtime_baseline_mode=skipped' "
    "'ctfos_runtime_baseline_reason=no_regular_source_binding'; "
    "exit 0; fi; "
    "case \"${target##*/}\" in *.[zZ][iI][pP]) "
    "printf '%s\\n' 'ctfos_runtime_baseline_mode=skipped' "
    "'ctfos_runtime_baseline_reason=archive_primary_non_executable'; "
    "exit 0;; esac; "
    "size=$(/usr/bin/stat --format=%s -- \"$target\"); stat_rc=$?; "
    "if [ \"$stat_rc\" -ne 0 ]; then "
    "printf '%s\\n' 'ctfos_runtime_baseline_error=source_stat_failed' "
    ">&2; exit 2; fi; "
    f"if [ \"$size\" -gt {_PWN_ADAPTER_PRIMARY_MAX_BYTES} ]; then "
    "printf '%s\\n' 'ctfos_runtime_baseline_mode=skipped' "
    "'ctfos_runtime_baseline_reason=source_size_limit_exceeded'; "
    "exit 0; fi; "
    "octets=$(/usr/bin/od -An -N4 -tu1 -- \"$target\"); magic_rc=$?; "
    "if [ \"$magic_rc\" -ne 0 ]; then "
    "printf '%s\\n' 'ctfos_runtime_baseline_error=source_magic_read_failed' "
    ">&2; exit 2; fi; "
    "set -- $octets; supported=false; "
    "if [ \"${1:-}\" = 127 ] && [ \"${2:-}\" = 69 ] && "
    "[ \"${3:-}\" = 76 ] && [ \"${4:-}\" = 70 ]; then "
    "supported=true; "
    "elif [ \"${1:-}\" = 35 ] && [ \"${2:-}\" = 33 ]; then "
    "supported=true; fi; "
    "if [ \"$supported\" != true ]; then "
    "printf '%s\\n' 'ctfos_runtime_baseline_mode=skipped' "
    "'ctfos_runtime_baseline_reason=unsupported_primary_format'; "
    "exit 0; fi; "
    "staged=$(/usr/bin/mktemp "
    "\"$work_root/ctfos-pwn-baseline.XXXXXX\"); mktemp_rc=$?; "
    "if [ \"$mktemp_rc\" -ne 0 ] || [ -z \"$staged\" ]; then "
    "printf '%s\\n' 'ctfos_runtime_baseline_error=staging_failed' "
    ">&2; exit 2; fi; "
    "status=${staged}.status; "
    "trap '/usr/bin/rm -f -- \"$staged\" \"$status\"' "
    "EXIT HUP INT TERM; "
    "if ! /usr/bin/cp -- \"$target\" \"$staged\"; then "
    "printf '%s\\n' 'ctfos_runtime_baseline_error=staging_failed' "
    ">&2; exit 2; fi; "
    "if ! /usr/bin/chmod 0500 -- \"$staged\"; then "
    "printf '%s\\n' 'ctfos_runtime_baseline_error=staging_failed' "
    ">&2; exit 2; fi; "
    "{ /usr/bin/timeout --signal=TERM --kill-after=1 3 "
    "\"$staged\" </dev/null; "
    "printf '%s\\n' \"$?\" >\"$status\"; "
    "} 2>&1 | /usr/bin/head -c 65536; pipe_rc=$?; "
    "if [ -r \"$status\" ]; then "
    "IFS= read -r rc <\"$status\" || rc=unknown; "
    "else rc=unknown; fi; "
    "printf '\\nctfos_runtime_baseline_exit=%s "
    "pipe_exit=%s\\n' \"$rc\" \"$pipe_rc\"; exit 0"
)


_ZIP_PRIMARY_INVENTORY = (
    f"MAX_OUTER_BYTES = {_PWN_ADAPTER_PRIMARY_MAX_BYTES}\n"
    f"MAX_ENTRIES = {_PWN_ZIP_MAX_ENTRIES}\n"
    f"MAX_OUTPUT_BYTES = {_PWN_ZIP_MAX_OUTPUT_BYTES}\n"
    r'''
import hashlib
import json
import os
import stat
import struct
import sys
import unicodedata

KIND = "ctfos_pwn_zip_inventory"
MAX_CENTRAL_DIRECTORY_BYTES = 1024 * 1024
MAX_ENTRY_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
MAX_RATIO = 200
MAX_RATIO_FLOOR_BYTES = 1024 * 1024
MAX_NAME_CHARACTERS = 64
MAX_DECLARED_NAME_BYTES = 512
MAX_DECLARED_EXTRA_BYTES = 4096
MAX_DECLARED_COMMENT_BYTES = 4096
SUPPORTED_COMPRESSION_METHODS = {0, 8, 12, 14, 93}
ENCRYPTION_FLAG_MASK = 0x2041
ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06")
EOCD_SIGNATURE = b"PK\x05\x06"
CENTRAL_SIGNATURE = b"PK\x01\x02"
LOCAL_SIGNATURE = b"PK\x03\x04"
CENTRAL_HEADER = struct.Struct("<4s6H3L5H2L")


def encoded(record):
    return (
        json.dumps(
            record,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def emit_one(mode, reason, *, error=False, **values):
    record = {"kind": KIND, "mode": mode, "reason": reason, **values}
    payload = encoded(record)
    if len(payload) > MAX_OUTPUT_BYTES:
        payload = b'{"kind":"ctfos_pwn_zip_inventory","mode":"error","reason":"output_limit_exceeded"}\n'
    stream = sys.stderr.buffer if error else sys.stdout.buffer
    stream.write(payload)


def stop(mode, reason, *, code=0, error=False, **values):
    emit_one(mode, reason, error=error, **values)
    raise SystemExit(code)


def identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def sanitized_name(value):
    visible = []
    for character in value[:MAX_NAME_CHARACTERS]:
        codepoint = ord(character)
        visible.append(
            character
            if codepoint >= 0x20
            and codepoint != 127
            and not unicodedata.category(character).startswith("C")
            else "\ufffd"
        )
    if len(value) > MAX_NAME_CHARACTERS:
        visible.append("...")
    return "".join(visible)


def extra_field_ids(value):
    identifiers = []
    cursor = 0
    while cursor < len(value):
        if len(value) - cursor < 4:
            return None
        identifier, field_size = struct.unpack_from("<HH", value, cursor)
        cursor += 4
        if cursor + field_size > len(value):
            return None
        identifiers.append(identifier)
        cursor += field_size
    return identifiers


if len(sys.argv) != 2:
    stop("error", "invalid_argv", code=2, error=True)
source = sys.argv[1]
try:
    lexical = os.lstat(source)
except OSError:
    stop("skipped", "no_regular_source_binding")
if stat.S_ISLNK(lexical.st_mode):
    stop("error", "symlink_source_binding", code=2, error=True)
if not stat.S_ISREG(lexical.st_mode):
    stop("skipped", "no_regular_source_binding")
if lexical.st_size > MAX_OUTER_BYTES:
    stop(
        "skipped",
        "source_size_limit_exceeded",
        source_size_bytes=lexical.st_size,
    )

flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
flags |= getattr(os, "O_NONBLOCK", 0)
flags |= getattr(os, "O_NOFOLLOW", 0)
try:
    descriptor = os.open(source, flags)
except OSError:
    stop("error", "source_open_failed", code=2, error=True)
try:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or identity(before) != identity(lexical)
        or before.st_size > MAX_OUTER_BYTES
    ):
        stop("error", "source_binding_changed", code=2, error=True)
    try:
        magic = os.pread(descriptor, 4, 0)
    except OSError:
        stop("error", "source_magic_read_failed", code=2, error=True)
    if magic not in ZIP_MAGICS:
        stop("skipped", "unsupported_primary_format")

    tail_size = min(before.st_size, 22 + 65535)
    tail_offset = before.st_size - tail_size
    try:
        tail = os.pread(descriptor, tail_size, tail_offset)
    except OSError:
        stop("error", "source_metadata_read_failed", code=2, error=True)
    relative_eocd = tail.rfind(EOCD_SIGNATURE)
    if relative_eocd < 0 or len(tail) - relative_eocd < 22:
        stop("unsafe", "invalid_end_of_central_directory")
    try:
        (
            _signature,
            disk_number,
            central_disk,
            entries_on_disk,
            entry_count,
            central_size,
            central_offset,
            comment_size,
        ) = struct.unpack_from("<4s4H2LH", tail, relative_eocd)
    except struct.error:
        stop("unsafe", "invalid_end_of_central_directory")
    eocd_offset = tail_offset + relative_eocd
    if relative_eocd + 22 + comment_size != len(tail):
        stop("unsafe", "invalid_archive_termination")
    if (
        disk_number != 0
        or central_disk != 0
        or entries_on_disk != entry_count
    ):
        stop("unsafe", "multi_disk_archive_unsupported")
    if (
        entry_count == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
    ):
        stop("unsafe", "zip64_archive_unsupported")
    if entry_count > MAX_ENTRIES:
        stop(
            "unsafe",
            "entry_count_limit_exceeded",
            entry_count=entry_count,
        )
    if central_size > MAX_CENTRAL_DIRECTORY_BYTES:
        stop(
            "unsafe",
            "central_directory_size_limit_exceeded",
            central_directory_bytes=central_size,
            entry_count=entry_count,
        )
    if central_offset + central_size != eocd_offset:
        stop("unsafe", "invalid_central_directory_binding")

    # EOCD counts are attacker-declared. Pre-scan the bounded central
    # directory before ZipFile can eagerly materialize ZipInfo objects.
    try:
        central_blob = os.pread(descriptor, central_size, central_offset)
    except OSError:
        stop("error", "source_metadata_read_failed", code=2, error=True)
    if len(central_blob) != central_size:
        stop("unsafe", "invalid_central_directory")
    central_records = []
    cursor = 0
    while cursor < len(central_blob):
        if len(central_records) >= MAX_ENTRIES:
            stop(
                "unsafe",
                "entry_count_limit_exceeded",
                entry_count=len(central_records) + 1,
            )
        if len(central_blob) - cursor < CENTRAL_HEADER.size:
            stop("unsafe", "invalid_central_directory")
        try:
            central = CENTRAL_HEADER.unpack_from(central_blob, cursor)
        except struct.error:
            stop("unsafe", "invalid_central_directory")
        (
            signature,
            _version_made,
            _version_needed,
            flag_bits,
            compression_method,
            _modified_time,
            _modified_date,
            _crc32,
            compressed_size,
            uncompressed_size,
            name_size,
            extra_size,
            entry_comment_size,
            start_disk,
            _internal_attributes,
            external_attributes,
            local_header_offset,
        ) = central
        if signature != CENTRAL_SIGNATURE:
            stop("unsafe", "invalid_central_directory")
        if (
            name_size > MAX_DECLARED_NAME_BYTES
            or extra_size > MAX_DECLARED_EXTRA_BYTES
            or entry_comment_size > MAX_DECLARED_COMMENT_BYTES
        ):
            stop("unsafe", "central_entry_metadata_limit_exceeded")
        record_size = (
            CENTRAL_HEADER.size
            + name_size
            + extra_size
            + entry_comment_size
        )
        if cursor + record_size > len(central_blob):
            stop("unsafe", "invalid_central_directory")
        if (
            start_disk != 0
            or compressed_size == 0xFFFFFFFF
            or uncompressed_size == 0xFFFFFFFF
            or local_header_offset == 0xFFFFFFFF
        ):
            stop("unsafe", "zip64_archive_unsupported")
        if local_header_offset >= central_offset or os.pread(
            descriptor,
            4,
            local_header_offset,
        ) != LOCAL_SIGNATURE:
            stop("unsafe", "invalid_local_header_binding")
        central_records.append(
            (
                flag_bits,
                compression_method,
                compressed_size,
                uncompressed_size,
                external_attributes,
                local_header_offset,
            )
        )
        cursor += record_size
    if len(central_records) != entry_count:
        stop("unsafe", "central_directory_count_mismatch")

    # Import only after descriptor, size, magic, EOCD, and entry-count
    # admission. ZipFile reads central-directory metadata; entry content APIs
    # are deliberately never called.
    import zipfile

    try:
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as source_file:
            with zipfile.ZipFile(
                source_file,
                mode="r",
                allowZip64=False,
            ) as archive:
                infos = archive.infolist()
    except Exception:
        stop("unsafe", "invalid_archive")
    if len(infos) != entry_count or len(infos) > MAX_ENTRIES:
        stop("unsafe", "central_directory_count_mismatch")
    for info, declared in zip(infos, central_records):
        if (
            info.flag_bits,
            info.compress_type,
            info.compress_size,
            info.file_size,
            info.external_attr,
            info.header_offset,
        ) != declared:
            stop("unsafe", "central_directory_parser_mismatch")

    names = [getattr(item, "orig_filename", item.filename) for item in infos]
    name_counts = {}
    for name in names:
        name_counts[name] = name_counts.get(name, 0) + 1

    total_uncompressed = sum(item.file_size for item in infos)
    archive_reasons = []
    if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
        archive_reasons.append("total_uncompressed_size_limit_exceeded")
    entries = []
    for ordinal, (info, original_name) in enumerate(
        zip(infos, names),
        start=1,
    ):
        reasons = []
        if not original_name:
            reasons.append("empty_name")
        if "\x00" in original_name:
            reasons.append("nul_in_name")
        if any(
            unicodedata.category(character).startswith("C")
            for character in original_name
        ):
            reasons.append("control_or_bidi_name")
        if "\\" in original_name:
            reasons.append("backslash_path")
        if original_name.startswith("/") or (
            len(original_name) >= 2
            and original_name[0].isalpha()
            and original_name[1] == ":"
        ):
            reasons.append("absolute_path")
        components = original_name.split("/")
        if ".." in components:
            reasons.append("parent_path")
        if "" in components[:-1]:
            reasons.append("empty_path_component")
        if name_counts.get(original_name, 0) > 1:
            reasons.append("duplicate_name")
        if len(original_name.encode("utf-8", errors="surrogatepass")) > 512:
            reasons.append("name_size_limit_exceeded")

        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            entry_type = "symlink"
            reasons.append("symlink_entry")
        elif info.is_dir():
            entry_type = "directory"
        elif mode and stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
            entry_type = "other"
            reasons.append("unsupported_entry_type")
        else:
            entry_type = "regular"
        encrypted = bool(info.flag_bits & ENCRYPTION_FLAG_MASK)
        if encrypted:
            reasons.append("encrypted_entry")
        extra_ids = extra_field_ids(info.extra)
        if extra_ids is None:
            reasons.append("invalid_extra_fields")
            extra_ids = []
        if 0x0001 in extra_ids:
            reasons.append("zip64_entry_unsupported")
        if info.compress_type == 99 or 0x9901 in extra_ids:
            reasons.append("aes_encrypted_entry")
        if info.compress_type not in SUPPORTED_COMPRESSION_METHODS:
            reasons.append("unsupported_compression_method")
        if len(info.extra) > 4096:
            reasons.append("extra_size_limit_exceeded")
        if info.compress_size > before.st_size:
            reasons.append("compressed_size_invalid")
        if info.file_size > MAX_ENTRY_UNCOMPRESSED_BYTES:
            reasons.append("uncompressed_size_limit_exceeded")
        if info.file_size > MAX_RATIO_FLOOR_BYTES and (
            info.compress_size == 0
            or info.file_size > info.compress_size * MAX_RATIO
        ):
            reasons.append("compression_ratio_limit_exceeded")
        reasons = sorted(set(reasons))
        entries.append(
            {
                "compressed_bytes": info.compress_size,
                "compression_method": info.compress_type,
                "encrypted": encrypted,
                "kind": "ctfos_pwn_zip_entry",
                "metadata_trust": "central_directory_declared",
                "mode": f"{mode:06o}",
                "name": sanitized_name(original_name),
                "name_sha256": hashlib.sha256(
                    original_name.encode(
                        "utf-8",
                        errors="surrogatepass",
                    )
                ).hexdigest(),
                "ordinal": ordinal,
                "reasons": reasons,
                "safe": not reasons,
                "type": entry_type,
                "uncompressed_bytes": info.file_size,
            }
        )
    unsafe_entry_count = sum(not item["safe"] for item in entries)
    if unsafe_entry_count:
        archive_reasons.append("unsafe_entries")
    archive_reasons = sorted(set(archive_reasons))

    after = os.fstat(descriptor)
    if identity(after) != identity(before):
        stop("error", "source_binding_changed", code=2, error=True)
    records = [
        {
            "archive_bytes": before.st_size,
            "central_directory_bytes": central_size,
            "entry_count": entry_count,
            "kind": KIND,
            "metadata_trust": "central_directory_declared",
            "mode": "unsafe" if archive_reasons else "observed",
            "reasons": archive_reasons,
            "safe": not archive_reasons,
            "total_uncompressed_bytes": total_uncompressed,
            "unsafe_entry_count": unsafe_entry_count,
        },
        *entries,
    ]
    output = b"".join(encoded(record) for record in records)
    if len(output) > MAX_OUTPUT_BYTES:
        stop(
            "unsafe",
            "output_limit_exceeded",
            entry_count=entry_count,
        )
    sys.stdout.buffer.write(output)
except Exception:
    # Do not expose parser diagnostics, challenge paths, or attacker-controlled
    # metadata if an unanticipated stdlib/OS failure escapes a guarded branch.
    stop("error", "inventory_failed_closed", code=2, error=True)
finally:
    try:
        os.close(descriptor)
    except OSError:
        pass
'''.strip()
)


class PwnAdapter(GenericAdapter):
    name = "pwn"

    def initial_observations(self) -> tuple[ExperimentSpec, ...]:
        return (
            ExperimentSpec(
                "binary_metadata",
                "identify format, architecture, and mitigations",
                (
                    "/bin/sh",
                    "-lc",
                    _BINARY_METADATA,
                    "ctfos-pwn-binary-metadata",
                    "{primary}",
                ),
                "architecture and mitigation table",
                "binary is executable and mitigations are recorded",
                "no executable challenge input exists",
            ),
            ExperimentSpec(
                "runtime_baseline",
                "observe normal and malformed-input behavior",
                (
                    "/bin/sh",
                    "-lc",
                    _RUNTIME_BASELINE,
                    "ctfos-pwn-runtime-baseline",
                    "{primary}",
                ),
                "bounded stdout/stderr and explicit child exit status",
                "behavior is repeatable or a crash is observed",
                "bounded runner cannot execute the binary",
                "light",
                15,
            ),
            ExperimentSpec(
                "zip_inventory",
                "inventory bounded metadata for a ZIP primary without extraction",
                (
                    "/usr/bin/python3",
                    "-I",
                    "-c",
                    _ZIP_PRIMARY_INVENTORY,
                    "{primary}",
                ),
                "bounded ASCII JSONL archive and entry metadata",
                "safe entries and archive hazards are recorded deterministically",
                "primary is not an applicable bounded regular ZIP archive",
                "light",
                15,
            ),
        )

    def progress_markers(self) -> tuple[ProgressMarker, ...]:
        # These are capabilities, not a strict ladder: a solve may legitimately
        # skip leak/write depending on the vulnerability.
        return tuple(
            ProgressMarker(key, label, "executed run plus exact locator")
            for key, label in (
                ("crash", "controlled crash"),
                ("control", "input controls relevant state"),
                ("leak", "useful disclosure primitive"),
                ("write", "useful write primitive"),
                ("code_execution", "controlled code execution"),
                ("flag_read", "flag source reached"),
            )
        )

    def proof_policy(self, *, remote: bool = False) -> ProofPolicy:
        return ProofPolicy(
            mode="success_distribution" if remote else "deterministic",
            clean_repetitions=3,
            remote_repetitions=0,
            trial_count=10 if remote else 0,
            minimum_success_rate=0.7 if remote else None,
            notes="race exploits report the full success/failure distribution",
        )

    def failure_labels(self) -> tuple[str, ...]:
        return (
            "no_crash",
            "offset_unstable",
            "primitive_not_exploitable",
            "remote_layout_mismatch",
            "model_refusal",
        )

    def captain_guidance(self) -> str:
        return (
            "Treat checksec and runtime behavior as independent evidence. Track "
            "capabilities as a set, not a mandatory linear ladder. Separate "
            "path validation from actually reading the intended flag."
        )
