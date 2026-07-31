#!/usr/bin/env python3
"""Run one hash-bound Rev target through one fixed real runtime.

The data-only runtime specification selects PE/Wine, JVM, .NET, WASM/WASI,
native ELF, or qemu-user ELF execution.  It also binds the exact source,
explicit target argv, working directory, and every declared dependency.
Candidate values, success markers, environment additions, shell fragments,
and output expectations are not part of the schema.

DEX/APK specs are parsed but fail closed because this image deliberately has
no Android emulator or ART/Dalvik execution runtime.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Iterator, Mapping, Sequence

import stdin_exec


CHALLENGE_ROOT = Path("/challenge")
WORK_ROOT = Path("/work")
PROTOCOL = "ctfos.rev.runtime.v1"
MAX_DOCUMENT_BYTES = 256 * 1024
MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_TOTAL_FILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_DEPENDENCIES = 128
MAX_ARGV = 64
MAX_ARGUMENT_BYTES = 4096
MAX_TOTAL_ARGUMENT_BYTES = 32 * 1024
READ_CHUNK_BYTES = 1024 * 1024
USAGE = (
    "Usage: runtime_exec.py --spec /work/RELATIVE_JSON "
    "--input /work/RELATIVE_FILE"
)
WASM_HELPER = "/opt/ctf-templates/rev/wasm_wasi_exec.mjs"

_ROOT_KEYS = frozenset(
    {
        "argv",
        "dependencies",
        "format",
        "options",
        "protocol",
        "runtime",
        "schema_version",
        "source",
    }
)
_FILE_KEYS = frozenset({"path", "sha256", "size_bytes"})
_OPTIONS_KEYS = frozenset(
    {
        "architecture",
        "main_class",
        "qemu_ld_prefix",
        "wasm_entrypoint",
        "working_directory",
    }
)
_FORMAT_RUNTIME: Mapping[str, frozenset[str]] = {
    "apk": frozenset({"unsupported"}),
    "dex": frozenset({"unsupported"}),
    "dotnet": frozenset({"dotnet", "mono"}),
    "elf": frozenset({"native", "qemu-user"}),
    "java-class": frozenset({"java"}),
    "java-jar": frozenset({"java"}),
    "pe": frozenset({"wine"}),
    "wasm": frozenset({"node-wasi"}),
}
_QEMU_ARCHES = frozenset(
    {
        "aarch64",
        "arm",
        "i386",
        "m68k",
        "mips",
        "mipsel",
        "mips64",
        "mips64el",
        "ppc",
        "ppc64",
        "ppc64le",
        "riscv32",
        "riscv64",
        "s390x",
        "sh4",
        "sh4eb",
        "sparc",
        "sparc32plus",
        "sparc64",
        "x86_64",
    }
)
_QEMU_BINARIES = {
    architecture: f"/usr/bin/qemu-{architecture}-static"
    for architecture in _QEMU_ARCHES
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_JAVA_CLASS = re.compile(
    r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$"
)
_WASM_EXPORT = re.compile(r"^[A-Za-z_$][A-Za-z0-9_.$-]{0,255}$")
_ELF_MACHINE_ARCHES: Mapping[int, frozenset[str]] = {
    2: frozenset({"sparc"}),
    3: frozenset({"i386"}),
    4: frozenset({"m68k"}),
    8: frozenset({"mips", "mipsel", "mips64", "mips64el"}),
    18: frozenset({"sparc32plus"}),
    20: frozenset({"ppc"}),
    21: frozenset({"ppc64", "ppc64le"}),
    22: frozenset({"s390x"}),
    40: frozenset({"arm"}),
    42: frozenset({"sh4", "sh4eb"}),
    43: frozenset({"sparc64"}),
    62: frozenset({"x86_64"}),
    183: frozenset({"aarch64"}),
    243: frozenset({"riscv32", "riscv64"}),
}


class RuntimeExecError(RuntimeError):
    """Stable, bounded pre-execution or transport failure."""

    def __init__(self, code: str, *, exit_code: int = 125) -> None:
        super().__init__(code)
        self.code = code
        self.exit_code = exit_code


def _exact_dict(
    value: object,
    keys: frozenset[str],
    code: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise RuntimeExecError(code)
    return value


def _safe_path(value: object, *, directory: bool = False) -> str:
    if (
        type(value) is not str
        or not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
    ):
        raise RuntimeExecError("runtime_path_invalid")
    if value == ".":
        if directory:
            return value
        raise RuntimeExecError("runtime_path_invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise RuntimeExecError("runtime_path_invalid") from error
    parts = value.split("/")
    if (
        len(encoded) > 4096
        or value.endswith("/")
        or any(
            not part
            or part in {".", ".."}
            or len(part.encode("utf-8")) > 255
            for part in parts
        )
        or not all(character.isprintable() for character in value)
    ):
        raise RuntimeExecError("runtime_path_invalid")
    return value


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeExecError("runtime_duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> object:
    raise RuntimeExecError("runtime_nonfinite_number")


def _canonical_bytes(value: object) -> bytes:
    try:
        payload = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise RuntimeExecError("runtime_document_invalid") from error
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise RuntimeExecError("runtime_document_too_large")
    return payload


def _file_record(value: object) -> dict[str, object]:
    item = _exact_dict(
        value,
        _FILE_KEYS,
        "runtime_file_schema_invalid",
    )
    path = _safe_path(item["path"])
    digest = item["sha256"]
    size = item["size_bytes"]
    if type(digest) is not str or _SHA256.fullmatch(digest) is None:
        raise RuntimeExecError("runtime_file_hash_invalid")
    if type(size) is not int or not 0 <= size <= MAX_FILE_BYTES:
        raise RuntimeExecError("runtime_file_size_invalid")
    return {"path": path, "sha256": digest, "size_bytes": size}


def _parse_spec(payload: bytes) -> dict[str, object]:
    if not 1 <= len(payload) <= MAX_DOCUMENT_BYTES:
        raise RuntimeExecError("runtime_document_size_invalid")
    try:
        root = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except RuntimeExecError:
        raise
    except (
        RecursionError,
        UnicodeError,
        json.JSONDecodeError,
    ) as error:
        raise RuntimeExecError("runtime_document_invalid") from error
    item = _exact_dict(root, _ROOT_KEYS, "runtime_spec_schema_invalid")
    if item["schema_version"] != 1 or item["protocol"] != PROTOCOL:
        raise RuntimeExecError("runtime_protocol_invalid")
    binary_format = item["format"]
    runtime = item["runtime"]
    if (
        type(binary_format) is not str
        or binary_format not in _FORMAT_RUNTIME
        or type(runtime) is not str
        or runtime not in _FORMAT_RUNTIME[binary_format]
    ):
        raise RuntimeExecError("runtime_selector_invalid")
    source = _file_record(item["source"])
    raw_dependencies = item["dependencies"]
    if (
        type(raw_dependencies) is not list
        or len(raw_dependencies) > MAX_DEPENDENCIES
    ):
        raise RuntimeExecError("runtime_dependencies_invalid")
    dependencies = [_file_record(value) for value in raw_dependencies]
    dependency_paths = tuple(
        str(value["path"]) for value in dependencies
    )
    if (
        dependency_paths != tuple(sorted(dependency_paths))
        or len(set(dependency_paths)) != len(dependency_paths)
        or source["path"] in dependency_paths
    ):
        raise RuntimeExecError("runtime_dependencies_not_canonical")
    total_size = int(source["size_bytes"]) + sum(
        int(value["size_bytes"]) for value in dependencies
    )
    if total_size > MAX_TOTAL_FILE_BYTES:
        raise RuntimeExecError("runtime_files_too_large")

    raw_argv = item["argv"]
    if type(raw_argv) is not list or len(raw_argv) > MAX_ARGV:
        raise RuntimeExecError("runtime_argv_invalid")
    total_argument_bytes = 0
    argv: list[str] = []
    for value in raw_argv:
        if type(value) is not str or "\x00" in value:
            raise RuntimeExecError("runtime_argv_invalid")
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise RuntimeExecError("runtime_argv_invalid") from error
        if (
            len(encoded) > MAX_ARGUMENT_BYTES
            or not all(character.isprintable() for character in value)
        ):
            raise RuntimeExecError("runtime_argv_invalid")
        total_argument_bytes += len(encoded)
        argv.append(value)
    if total_argument_bytes > MAX_TOTAL_ARGUMENT_BYTES:
        raise RuntimeExecError("runtime_argv_invalid")

    options = _exact_dict(
        item["options"],
        _OPTIONS_KEYS,
        "runtime_options_schema_invalid",
    )
    architecture = options["architecture"]
    if architecture is not None and (
        type(architecture) is not str
        or architecture not in _QEMU_ARCHES
    ):
        raise RuntimeExecError("runtime_architecture_invalid")
    if (architecture is not None) is not (runtime == "qemu-user"):
        raise RuntimeExecError("runtime_architecture_invalid")
    main_class = options["main_class"]
    class_required = binary_format == "java-class"
    class_allowed = binary_format in {"java-class", "java-jar"}
    if (
        main_class is not None
        and (
            type(main_class) is not str
            or _JAVA_CLASS.fullmatch(main_class) is None
        )
    ) or (class_required and main_class is None) or (
        not class_allowed and main_class is not None
    ):
        raise RuntimeExecError("runtime_main_class_invalid")
    wasm_entrypoint = options["wasm_entrypoint"]
    if (
        wasm_entrypoint is not None
        and (
            type(wasm_entrypoint) is not str
            or _WASM_EXPORT.fullmatch(wasm_entrypoint) is None
        )
    ) or (
        (wasm_entrypoint is not None) is not (binary_format == "wasm")
    ):
        raise RuntimeExecError("runtime_wasm_entrypoint_invalid")
    qemu_prefix = options["qemu_ld_prefix"]
    if qemu_prefix is not None:
        qemu_prefix = _safe_path(qemu_prefix, directory=True)
    if qemu_prefix is not None and runtime != "qemu-user":
        raise RuntimeExecError("runtime_qemu_prefix_invalid")
    if qemu_prefix is not None and not any(
        str(value["path"]).startswith(qemu_prefix + "/")
        for value in dependencies
    ):
        raise RuntimeExecError("runtime_qemu_prefix_unbound")
    working_directory = _safe_path(
        options["working_directory"],
        directory=True,
    )
    file_paths = (str(source["path"]), *dependency_paths)
    if working_directory != "." and not any(
        path.startswith(working_directory + "/")
        for path in file_paths
    ):
        raise RuntimeExecError("runtime_working_directory_unbound")

    canonical = {
        "argv": argv,
        "dependencies": dependencies,
        "format": binary_format,
        "options": {
            "architecture": architecture,
            "main_class": main_class,
            "qemu_ld_prefix": qemu_prefix,
            "wasm_entrypoint": wasm_entrypoint,
            "working_directory": working_directory,
        },
        "protocol": PROTOCOL,
        "runtime": runtime,
        "schema_version": 1,
        "source": source,
    }
    if _canonical_bytes(canonical) != payload:
        raise RuntimeExecError("runtime_spec_not_canonical")
    return canonical


def _stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return stdin_exec._stable_file_identity(metadata)


def _read_hash_bound(
    descriptor: int,
    before: os.stat_result,
    *,
    expected_sha256: str,
    expected_size: int,
    maximum_bytes: int,
) -> bytes:
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_mode & (stat.S_ISUID | stat.S_ISGID)
        or before.st_size != expected_size
        or not 0 <= expected_size <= maximum_bytes
    ):
        raise RuntimeExecError("runtime_file_metadata_mismatch")
    digest = hashlib.sha256()
    prefix = bytearray()
    offset = 0
    try:
        while offset < expected_size:
            chunk = os.pread(
                descriptor,
                min(READ_CHUNK_BYTES, expected_size - offset),
                offset,
            )
            if not chunk:
                raise RuntimeExecError("runtime_file_read_incomplete")
            digest.update(chunk)
            if len(prefix) < 4096:
                prefix.extend(chunk[: 4096 - len(prefix)])
            offset += len(chunk)
        if os.pread(descriptor, 1, offset):
            raise RuntimeExecError("runtime_file_size_mismatch")
        after = os.fstat(descriptor)
    except RuntimeExecError:
        raise
    except OSError as error:
        raise RuntimeExecError("runtime_file_read_failed") from error
    if (
        _stable_identity(after) != _stable_identity(before)
        or digest.hexdigest() != expected_sha256
    ):
        raise RuntimeExecError("runtime_file_binding_mismatch")
    return bytes(prefix)


@contextmanager
def _open_directory_beneath(
    root: Path,
    relative: str,
) -> Iterator[int]:
    components = () if relative == "." else tuple(relative.split("/"))
    descriptors: list[int] = []
    try:
        try:
            current = os.open(root, stdin_exec._directory_flags())
        except OSError as error:
            raise RuntimeExecError(
                "runtime_working_directory_unavailable"
            ) from error
        descriptors.append(current)
        for component in components:
            try:
                child = os.open(
                    component,
                    stdin_exec._directory_flags(),
                    dir_fd=current,
                )
            except OSError as error:
                raise RuntimeExecError(
                    "runtime_working_directory_unavailable"
                ) from error
            descriptors.append(child)
            if not stat.S_ISDIR(os.fstat(child).st_mode):
                raise RuntimeExecError(
                    "runtime_working_directory_invalid"
                )
            current = child
        yield current
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _verify_exact_challenge_tree(
    root: Path,
    expected_files: frozenset[str],
) -> None:
    """Reject every runtime-visible challenge file outside the bound closure."""

    expected_directories = {"."}
    for locator in expected_files:
        parts = locator.split("/")
        expected_directories.update(
            "/".join(parts[:index])
            for index in range(1, len(parts))
        )
    observed_files: set[str] = set()
    observed_directories: set[str] = {"."}
    descriptors: list[int] = []
    pending: list[tuple[int, str]] = []
    try:
        try:
            root_descriptor = os.open(root, stdin_exec._directory_flags())
        except OSError as error:
            raise RuntimeExecError(
                "runtime_challenge_tree_unavailable"
            ) from error
        descriptors.append(root_descriptor)
        pending.append((root_descriptor, ""))
        while pending:
            directory_descriptor, prefix = pending.pop()
            try:
                entries = os.scandir(directory_descriptor)
            except OSError as error:
                raise RuntimeExecError(
                    "runtime_challenge_tree_unavailable"
                ) from error
            try:
                for entry in entries:
                    if (
                        not entry.name
                        or entry.name in {".", ".."}
                        or "/" in entry.name
                        or "\\" in entry.name
                    ):
                        raise RuntimeExecError(
                            "runtime_challenge_tree_invalid"
                        )
                    locator = (
                        f"{prefix}/{entry.name}" if prefix else entry.name
                    )
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except OSError as error:
                        raise RuntimeExecError(
                            "runtime_challenge_tree_unavailable"
                        ) from error
                    if stat.S_ISDIR(metadata.st_mode):
                        if locator not in expected_directories:
                            raise RuntimeExecError(
                                "runtime_unbound_challenge_path"
                            )
                        try:
                            child = os.open(
                                entry.name,
                                stdin_exec._directory_flags(),
                                dir_fd=directory_descriptor,
                            )
                        except OSError as error:
                            raise RuntimeExecError(
                                "runtime_challenge_tree_unavailable"
                            ) from error
                        descriptors.append(child)
                        observed_directories.add(locator)
                        pending.append((child, locator))
                    elif stat.S_ISREG(metadata.st_mode):
                        if locator not in expected_files:
                            raise RuntimeExecError(
                                "runtime_unbound_challenge_path"
                            )
                        observed_files.add(locator)
                    else:
                        raise RuntimeExecError(
                            "runtime_challenge_tree_invalid"
                        )
                    if (
                        len(observed_files) > MAX_DEPENDENCIES + 1
                        or len(observed_directories)
                        > (MAX_DEPENDENCIES + 1) * 16
                    ):
                        raise RuntimeExecError(
                            "runtime_challenge_tree_too_large"
                        )
            except OSError as error:
                raise RuntimeExecError(
                    "runtime_challenge_tree_unavailable"
                ) from error
            finally:
                entries.close()
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
    if (
        observed_files != set(expected_files)
        or observed_directories != expected_directories
    ):
        raise RuntimeExecError("runtime_challenge_tree_mismatch")


def _read_work_file(
    argument: str,
    *,
    work_root: Path,
    maximum_bytes: int,
) -> bytes:
    components = stdin_exec._relative_components(argument, "/work")
    with stdin_exec._open_beneath(
        work_root,
        components,
        label="runtime_work_file",
    ) as (descriptor, metadata):
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 0 <= metadata.st_size <= maximum_bytes
        ):
            raise RuntimeExecError("runtime_work_file_invalid")
        chunks: list[bytes] = []
        offset = 0
        try:
            while offset < metadata.st_size:
                chunk = os.pread(
                    descriptor,
                    min(64 * 1024, metadata.st_size - offset),
                    offset,
                )
                if not chunk:
                    raise RuntimeExecError(
                        "runtime_work_file_read_incomplete"
                    )
                chunks.append(chunk)
                offset += len(chunk)
            after = os.fstat(descriptor)
        except RuntimeExecError:
            raise
        except OSError as error:
            raise RuntimeExecError(
                "runtime_work_file_read_failed"
            ) from error
        if _stable_identity(after) != _stable_identity(metadata):
            raise RuntimeExecError("runtime_work_file_changed")
        return b"".join(chunks)


def _elf_architecture(header: bytes) -> frozenset[str]:
    if len(header) < 20 or header[:4] != b"\x7fELF":
        raise RuntimeExecError("runtime_source_format_mismatch")
    if header[5] == 1:
        byte_order = "little"
    elif header[5] == 2:
        byte_order = "big"
    else:
        raise RuntimeExecError("runtime_elf_header_invalid")
    machine = int.from_bytes(header[18:20], byte_order)
    values = _ELF_MACHINE_ARCHES.get(machine)
    if values is None:
        raise RuntimeExecError("runtime_elf_architecture_unsupported")
    if machine == 8:
        bits = 64 if header[4] == 2 else 32
        suffix = "el" if byte_order == "little" else ""
        return frozenset({f"mips{bits if bits == 64 else ''}{suffix}"})
    if machine == 21:
        return frozenset(
            {"ppc64le" if byte_order == "little" else "ppc64"}
        )
    if machine == 42:
        return frozenset(
            {"sh4" if byte_order == "little" else "sh4eb"}
        )
    if machine == 243:
        return frozenset({"riscv64" if header[4] == 2 else "riscv32"})
    return values


def _validate_source_format(
    spec: Mapping[str, object],
    header: bytes,
) -> None:
    binary_format = str(spec["format"])
    options = spec["options"]
    assert isinstance(options, dict)
    if binary_format == "elf":
        architectures = _elf_architecture(header)
        if spec["runtime"] == "qemu-user":
            if options["architecture"] not in architectures:
                raise RuntimeExecError(
                    "runtime_qemu_architecture_mismatch"
                )
        else:
            host = platform.machine().casefold()
            compatible = {
                "aarch64": frozenset({"aarch64"}),
                "amd64": frozenset({"x86_64", "i386"}),
                "arm64": frozenset({"aarch64"}),
                "x86_64": frozenset({"x86_64", "i386"}),
            }.get(host, frozenset({host}))
            if architectures.isdisjoint(compatible):
                raise RuntimeExecError(
                    "runtime_native_architecture_mismatch"
                )
    elif binary_format in {"pe", "dotnet"}:
        if len(header) < 64 or header[:2] != b"MZ":
            raise RuntimeExecError("runtime_source_format_mismatch")
        pe_offset = int.from_bytes(header[60:64], "little")
        if pe_offset > len(header) - 4 or header[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise RuntimeExecError("runtime_pe_header_invalid")
    elif binary_format == "java-class":
        if header[:4] != b"\xca\xfe\xba\xbe":
            raise RuntimeExecError("runtime_source_format_mismatch")
        main_class = options["main_class"]
        assert isinstance(main_class, str)
        source = spec["source"]
        assert isinstance(source, dict)
        if not str(source["path"]).endswith(
            main_class.replace(".", "/") + ".class"
        ):
            raise RuntimeExecError("runtime_main_class_path_mismatch")
    elif binary_format in {"java-jar", "apk"}:
        if header[:4] not in {b"PK\x03\x04", b"PK\x05\x06"}:
            raise RuntimeExecError("runtime_source_format_mismatch")
    elif binary_format == "wasm":
        if header[:8] != b"\x00asm\x01\x00\x00\x00":
            raise RuntimeExecError("runtime_source_format_mismatch")
    elif binary_format == "dex":
        if not (
            len(header) >= 8
            and header[:4] == b"dex\n"
            and header[7] == 0
        ):
            raise RuntimeExecError("runtime_source_format_mismatch")


def _runtime_invocation(
    spec: Mapping[str, object],
) -> tuple[tuple[str, ...], str | None, dict[str, str]]:
    runtime = str(spec["runtime"])
    source = spec["source"]
    dependencies = spec["dependencies"]
    options = spec["options"]
    argv = spec["argv"]
    assert isinstance(source, dict)
    assert isinstance(dependencies, list)
    assert isinstance(options, dict)
    assert isinstance(argv, list)
    public_source = f"/challenge/{source['path']}"
    environment = dict(stdin_exec.FIXED_ENVIRONMENT)
    environment.update(
        {
            "NODE_NO_WARNINGS": "1",
            "TMPDIR": "/work/.ctfos-runtime-tmp",
        }
    )
    executable: str | None = None
    if runtime == "native":
        command = (public_source, *(str(value) for value in argv))
        executable = "<source-fd>"
    elif runtime == "qemu-user":
        architecture = str(options["architecture"])
        command = (
            _QEMU_BINARIES[architecture],
            public_source,
            *(str(value) for value in argv),
        )
        if options["qemu_ld_prefix"] is not None:
            environment["QEMU_LD_PREFIX"] = (
                f"/challenge/{options['qemu_ld_prefix']}"
            )
    elif runtime == "wine":
        environment.update(
            {
                "WINEDEBUG": "-all",
                "WINEPREFIX": "/work/.ctfos-wine-prefix",
            }
        )
        command = (
            "/usr/local/bin/wine",
            public_source,
            *(str(value) for value in argv),
        )
    elif runtime == "java":
        dependency_paths = [
            f"/challenge/{value['path']}"
            for value in dependencies
            if str(value["path"]).endswith((".jar", ".zip"))
        ]
        main_class = options["main_class"]
        if spec["format"] == "java-jar" and main_class is None:
            command = (
                "/usr/bin/java",
                "-jar",
                public_source,
                *(str(value) for value in argv),
            )
        else:
            classpath = [
                (
                    "/challenge"
                    if options["working_directory"] == "."
                    else f"/challenge/{options['working_directory']}"
                ),
                *dependency_paths,
            ]
            command = (
                "/usr/bin/java",
                "-cp",
                ":".join(classpath),
                str(main_class),
                *(str(value) for value in argv),
            )
    elif runtime in {"dotnet", "mono"}:
        host = "/usr/bin/dotnet" if runtime == "dotnet" else "/usr/bin/mono"
        command = (host, public_source, *(str(value) for value in argv))
    elif runtime == "node-wasi":
        command = (
            "/usr/bin/node",
            WASM_HELPER,
            "--module",
            public_source,
            "--entry",
            str(options["wasm_entrypoint"]),
            "--",
            *(str(value) for value in argv),
        )
    else:
        raise RuntimeExecError("runtime_unsupported_dex_apk")
    return command, executable, environment


def execute_runtime(
    spec_argument: str,
    input_argument: str,
    *,
    challenge_root: Path = CHALLENGE_ROOT,
    work_root: Path = WORK_ROOT,
) -> int:
    """Verify the complete spec and return the exact child process status."""

    payload = _read_work_file(
        spec_argument,
        work_root=work_root,
        maximum_bytes=MAX_DOCUMENT_BYTES,
    )
    spec = _parse_spec(payload)
    if spec["format"] in {"dex", "apk"}:
        raise RuntimeExecError("runtime_unsupported_dex_apk")
    input_components = stdin_exec._relative_components(
        input_argument,
        "/work",
    )
    source = spec["source"]
    dependencies = spec["dependencies"]
    options = spec["options"]
    assert isinstance(source, dict)
    assert isinstance(dependencies, list)
    assert isinstance(options, dict)
    expected_files = frozenset(
        str(record["path"]) for record in (source, *dependencies)
    )
    _verify_exact_challenge_tree(challenge_root, expected_files)

    runtime_tmp = work_root / ".ctfos-runtime-tmp"
    runtime_tmp.mkdir(mode=0o700, exist_ok=True)
    if not runtime_tmp.is_dir() or runtime_tmp.is_symlink():
        raise RuntimeExecError("runtime_temporary_directory_invalid")

    with ExitStack() as stack:
        opened: dict[str, tuple[int, os.stat_result, bytes]] = {}
        for record in (source, *dependencies):
            assert isinstance(record, dict)
            components = tuple(str(record["path"]).split("/"))
            descriptor, metadata = stack.enter_context(
                stdin_exec._open_beneath(
                    challenge_root,
                    components,
                    label="runtime_file",
                )
            )
            header = _read_hash_bound(
                descriptor,
                metadata,
                expected_sha256=str(record["sha256"]),
                expected_size=int(record["size_bytes"]),
                maximum_bytes=MAX_FILE_BYTES,
            )
            opened[str(record["path"])] = (
                descriptor,
                metadata,
                header,
            )
        source_descriptor, source_metadata, source_header = opened[
            str(source["path"])
        ]
        _validate_source_format(spec, source_header)
        if (
            spec["runtime"] == "native"
            and not source_metadata.st_mode & 0o111
        ):
            raise RuntimeExecError("runtime_source_not_executable")

        working_descriptor = stack.enter_context(
            _open_directory_beneath(
                challenge_root,
                str(options["working_directory"]),
            )
        )
        with stdin_exec._open_beneath(
            work_root,
            input_components,
            label="input",
        ) as (input_descriptor, input_metadata):
            stdin_payload = stdin_exec._read_stable_input(
                input_descriptor,
                input_metadata,
            )

        with stdin_exec._sealed_stdin_snapshot(
            stdin_payload
        ) as stdin_descriptor:
            _verify_exact_challenge_tree(
                challenge_root,
                expected_files,
            )
            command, executable, environment = _runtime_invocation(spec)
            if executable == "<source-fd>":
                executable = f"/proc/self/fd/{source_descriptor}"
            stdin_exec._disable_core_dumps()
            pass_fds = tuple(
                dict.fromkeys(
                    (
                        *(value[0] for value in opened.values()),
                        working_descriptor,
                    )
                )
            )
            try:
                completed = subprocess.run(
                    command,
                    executable=executable,
                    stdin=stdin_descriptor,
                    stdout=None,
                    stderr=None,
                    cwd=f"/proc/self/fd/{working_descriptor}",
                    env=environment,
                    close_fds=True,
                    pass_fds=pass_fds,
                    shell=False,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as error:
                raise RuntimeExecError("runtime_spawn_failed") from error
            if completed.returncode == 125:
                raise RuntimeExecError("runtime_child_transport_failed")
            return completed.returncode


def _parse_cli(argv: Sequence[str]) -> tuple[str, str]:
    if (
        len(argv) != 4
        or argv[0] != "--spec"
        or argv[2] != "--input"
        or not argv[1]
        or not argv[3]
    ):
        raise RuntimeExecError("invalid_cli", exit_code=2)
    return argv[1], argv[3]


def main(argv: Sequence[str] | None = None) -> int:
    selected = tuple(sys.argv[1:] if argv is None else argv)
    try:
        spec_argument, input_argument = _parse_cli(selected)
        return stdin_exec._preserve_target_status(
            execute_runtime(spec_argument, input_argument)
        )
    except (RuntimeExecError, stdin_exec.StdinExecError) as error:
        code = getattr(error, "code", "runtime_error")
        exit_code = getattr(error, "exit_code", 125)
        print(f"runtime_exec: {code}", file=sys.stderr)
        if exit_code == 2:
            print(USAGE, file=sys.stderr)
        return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
