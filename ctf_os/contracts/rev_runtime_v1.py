"""Strict execution contract for non-native Rev proof targets.

The contract is data only.  It cannot carry shell fragments, environment
variables, success markers, candidate values, or output expectations.  A
runtime consumer must independently re-read every declared source file and
verify the exact size and SHA-256 before executing the fixed runtime selected
by ``format`` and ``runtime``.

DEX and APK are intentionally representable but unsupported.  The sandbox
image does not contain Android ART/Dalvik and the image contract forbids an
Android emulator.  Consumers must reject those specs with the stable
``runtime_unsupported_dex_apk`` code instead of treating a decompiler as an
executable oracle.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence


REV_RUNTIME_V1_PROTOCOL = "ctfos.rev.runtime.v1"
REV_RUNTIME_V1_SCHEMA_VERSION = 1
REV_RUNTIME_V1_MAX_DOCUMENT_BYTES = 256 * 1024
REV_RUNTIME_V1_MAX_FILE_BYTES = 1024 * 1024 * 1024
REV_RUNTIME_V1_MAX_TOTAL_FILE_BYTES = 2 * 1024 * 1024 * 1024
REV_RUNTIME_V1_MAX_DEPENDENCIES = 128
REV_RUNTIME_V1_MAX_ARGV = 64
REV_RUNTIME_V1_MAX_ARGUMENT_BYTES = 4096
REV_RUNTIME_V1_MAX_TOTAL_ARGUMENT_BYTES = 32 * 1024

REV_RUNTIME_V1_FORMATS = frozenset(
    {
        "apk",
        "dex",
        "dotnet",
        "elf",
        "java-class",
        "java-jar",
        "pe",
        "wasm",
    }
)
REV_RUNTIME_V1_RUNTIMES = frozenset(
    {
        "dotnet",
        "java",
        "mono",
        "native",
        "node-wasi",
        "qemu-user",
        "unsupported",
        "wine",
    }
)
REV_RUNTIME_V1_QEMU_ARCHITECTURES = frozenset(
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

_FORMAT_RUNTIME = {
    "apk": "unsupported",
    "dex": "unsupported",
    "dotnet": frozenset({"dotnet", "mono"}),
    "elf": frozenset({"native", "qemu-user"}),
    "java-class": "java",
    "java-jar": "java",
    "pe": "wine",
    "wasm": "node-wasi",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_JAVA_CLASS = re.compile(
    r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$"
)
_WASM_EXPORT = re.compile(r"^[A-Za-z_$][A-Za-z0-9_.$-]{0,255}$")
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
_SPEC_KEYS = frozenset(
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


class RevRuntimeV1Error(ValueError):
    """Stable fail-closed contract error."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def canonical_json_bytes(value: object) -> bytes:
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
        raise RevRuntimeV1Error("runtime_document_invalid") from error
    if len(payload) > REV_RUNTIME_V1_MAX_DOCUMENT_BYTES:
        raise RevRuntimeV1Error("runtime_document_too_large")
    return payload


def _exact_dict(
    value: object,
    keys: frozenset[str],
    code: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise RevRuntimeV1Error(code)
    return value


def _safe_relative_path(value: object, *, directory: bool = False) -> str:
    if type(value) is not str or not value or value.startswith("/"):
        raise RevRuntimeV1Error("runtime_path_invalid")
    if "\\" in value or "\x00" in value:
        raise RevRuntimeV1Error("runtime_path_invalid")
    if value == ".":
        if directory:
            return value
        raise RevRuntimeV1Error("runtime_path_invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise RevRuntimeV1Error("runtime_path_invalid") from error
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
        raise RevRuntimeV1Error("runtime_path_invalid")
    return value


def _safe_optional_text(
    value: object,
    *,
    pattern: re.Pattern[str],
    code: str,
) -> str | None:
    if value is None:
        return None
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise RevRuntimeV1Error(code)
    return value


@dataclass(frozen=True, slots=True)
class RevRuntimeV1File:
    path: str
    sha256: str
    size_bytes: int

    @classmethod
    def from_mapping(cls, value: object) -> "RevRuntimeV1File":
        item = _exact_dict(
            value,
            _FILE_KEYS,
            "runtime_file_schema_invalid",
        )
        path = _safe_relative_path(item["path"])
        digest = item["sha256"]
        size = item["size_bytes"]
        if type(digest) is not str or _SHA256.fullmatch(digest) is None:
            raise RevRuntimeV1Error("runtime_file_hash_invalid")
        if (
            type(size) is not int
            or not 0 <= size <= REV_RUNTIME_V1_MAX_FILE_BYTES
        ):
            raise RevRuntimeV1Error("runtime_file_size_invalid")
        return cls(path=path, sha256=digest, size_bytes=size)

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True, slots=True)
class RevRuntimeV1Options:
    architecture: str | None
    main_class: str | None
    qemu_ld_prefix: str | None
    wasm_entrypoint: str | None
    working_directory: str

    @classmethod
    def from_mapping(cls, value: object) -> "RevRuntimeV1Options":
        item = _exact_dict(
            value,
            _OPTIONS_KEYS,
            "runtime_options_schema_invalid",
        )
        architecture = item["architecture"]
        if architecture is not None and (
            type(architecture) is not str
            or architecture not in REV_RUNTIME_V1_QEMU_ARCHITECTURES
        ):
            raise RevRuntimeV1Error("runtime_architecture_invalid")
        return cls(
            architecture=architecture,
            main_class=_safe_optional_text(
                item["main_class"],
                pattern=_JAVA_CLASS,
                code="runtime_main_class_invalid",
            ),
            qemu_ld_prefix=(
                None
                if item["qemu_ld_prefix"] is None
                else _safe_relative_path(
                    item["qemu_ld_prefix"],
                    directory=True,
                )
            ),
            wasm_entrypoint=_safe_optional_text(
                item["wasm_entrypoint"],
                pattern=_WASM_EXPORT,
                code="runtime_wasm_entrypoint_invalid",
            ),
            working_directory=_safe_relative_path(
                item["working_directory"],
                directory=True,
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "architecture": self.architecture,
            "main_class": self.main_class,
            "qemu_ld_prefix": self.qemu_ld_prefix,
            "wasm_entrypoint": self.wasm_entrypoint,
            "working_directory": self.working_directory,
        }


@dataclass(frozen=True, slots=True)
class RevRuntimeV1Spec:
    format: str
    runtime: str
    source: RevRuntimeV1File
    dependencies: tuple[RevRuntimeV1File, ...]
    argv: tuple[str, ...]
    options: RevRuntimeV1Options

    @classmethod
    def from_mapping(cls, value: object) -> "RevRuntimeV1Spec":
        item = _exact_dict(
            value,
            _SPEC_KEYS,
            "runtime_spec_schema_invalid",
        )
        if (
            item["schema_version"] != REV_RUNTIME_V1_SCHEMA_VERSION
            or item["protocol"] != REV_RUNTIME_V1_PROTOCOL
        ):
            raise RevRuntimeV1Error("runtime_protocol_invalid")
        binary_format = item["format"]
        runtime = item["runtime"]
        if (
            type(binary_format) is not str
            or binary_format not in REV_RUNTIME_V1_FORMATS
            or type(runtime) is not str
            or runtime not in REV_RUNTIME_V1_RUNTIMES
        ):
            raise RevRuntimeV1Error("runtime_selector_invalid")
        expected_runtime = _FORMAT_RUNTIME[binary_format]
        if (
            isinstance(expected_runtime, str)
            and runtime != expected_runtime
        ) or (
            isinstance(expected_runtime, frozenset)
            and runtime not in expected_runtime
        ):
            raise RevRuntimeV1Error("runtime_format_mismatch")

        source = RevRuntimeV1File.from_mapping(item["source"])
        raw_dependencies = item["dependencies"]
        if (
            type(raw_dependencies) is not list
            or len(raw_dependencies) > REV_RUNTIME_V1_MAX_DEPENDENCIES
        ):
            raise RevRuntimeV1Error("runtime_dependencies_invalid")
        dependencies = tuple(
            RevRuntimeV1File.from_mapping(dependency)
            for dependency in raw_dependencies
        )
        dependency_paths = tuple(
            dependency.path for dependency in dependencies
        )
        if (
            dependency_paths != tuple(sorted(dependency_paths))
            or len(set(dependency_paths)) != len(dependency_paths)
            or source.path in dependency_paths
        ):
            raise RevRuntimeV1Error("runtime_dependencies_not_canonical")
        total_bytes = source.size_bytes + sum(
            dependency.size_bytes for dependency in dependencies
        )
        if total_bytes > REV_RUNTIME_V1_MAX_TOTAL_FILE_BYTES:
            raise RevRuntimeV1Error("runtime_files_too_large")

        raw_argv = item["argv"]
        if (
            type(raw_argv) is not list
            or len(raw_argv) > REV_RUNTIME_V1_MAX_ARGV
        ):
            raise RevRuntimeV1Error("runtime_argv_invalid")
        arguments: list[str] = []
        argument_bytes = 0
        for argument in raw_argv:
            if type(argument) is not str or "\x00" in argument:
                raise RevRuntimeV1Error("runtime_argv_invalid")
            try:
                encoded = argument.encode("utf-8", errors="strict")
            except UnicodeEncodeError as error:
                raise RevRuntimeV1Error("runtime_argv_invalid") from error
            if (
                len(encoded) > REV_RUNTIME_V1_MAX_ARGUMENT_BYTES
                or not all(character.isprintable() for character in argument)
            ):
                raise RevRuntimeV1Error("runtime_argv_invalid")
            argument_bytes += len(encoded)
            arguments.append(argument)
        if argument_bytes > REV_RUNTIME_V1_MAX_TOTAL_ARGUMENT_BYTES:
            raise RevRuntimeV1Error("runtime_argv_invalid")

        options = RevRuntimeV1Options.from_mapping(item["options"])
        spec = cls(
            format=binary_format,
            runtime=runtime,
            source=source,
            dependencies=dependencies,
            argv=tuple(arguments),
            options=options,
        )
        spec._validate_cross_fields()
        if canonical_json_bytes(spec.to_dict()) != canonical_json_bytes(item):
            raise RevRuntimeV1Error("runtime_spec_not_canonical")
        return spec

    def _validate_cross_fields(self) -> None:
        architecture_required = self.runtime == "qemu-user"
        if (self.options.architecture is not None) is not architecture_required:
            raise RevRuntimeV1Error("runtime_architecture_invalid")
        class_required = self.format == "java-class"
        class_allowed = self.format in {"java-class", "java-jar"}
        if (
            (class_required and self.options.main_class is None)
            or (
                not class_allowed
                and self.options.main_class is not None
            )
        ):
            raise RevRuntimeV1Error("runtime_main_class_invalid")
        wasm_required = self.format == "wasm"
        if (self.options.wasm_entrypoint is not None) is not wasm_required:
            raise RevRuntimeV1Error("runtime_wasm_entrypoint_invalid")
        if (
            self.options.qemu_ld_prefix is not None
            and self.runtime != "qemu-user"
        ):
            raise RevRuntimeV1Error("runtime_qemu_prefix_invalid")
        if self.options.qemu_ld_prefix is not None:
            prefix = self.options.qemu_ld_prefix + "/"
            if not any(
                dependency.path.startswith(prefix)
                for dependency in self.dependencies
            ):
                raise RevRuntimeV1Error("runtime_qemu_prefix_unbound")

        file_paths = (self.source.path,) + tuple(
            dependency.path for dependency in self.dependencies
        )
        working = self.options.working_directory
        if working != "." and not any(
            path.startswith(working + "/") for path in file_paths
        ):
            raise RevRuntimeV1Error(
                "runtime_working_directory_unbound"
            )

    @property
    def supported(self) -> bool:
        return self.format not in {"apk", "dex"}

    @property
    def unsupported_reason(self) -> str | None:
        return None if self.supported else "runtime_unsupported_dex_apk"

    def require_supported(self) -> None:
        if not self.supported:
            raise RevRuntimeV1Error("runtime_unsupported_dex_apk")

    def to_dict(self) -> dict[str, object]:
        return {
            "argv": list(self.argv),
            "dependencies": [
                dependency.to_dict()
                for dependency in self.dependencies
            ],
            "format": self.format,
            "options": self.options.to_dict(),
            "protocol": REV_RUNTIME_V1_PROTOCOL,
            "runtime": self.runtime,
            "schema_version": REV_RUNTIME_V1_SCHEMA_VERSION,
            "source": self.source.to_dict(),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()


def build_rev_runtime_v1_spec(
    *,
    format: str,
    runtime: str,
    source: Mapping[str, object] | RevRuntimeV1File,
    dependencies: Iterable[
        Mapping[str, object] | RevRuntimeV1File
    ] = (),
    argv: Sequence[str] = (),
    architecture: str | None = None,
    main_class: str | None = None,
    qemu_ld_prefix: str | None = None,
    wasm_entrypoint: str | None = None,
    working_directory: str = ".",
) -> RevRuntimeV1Spec:
    """Build and round-trip one canonical runtime specification."""

    source_value = (
        source.to_dict()
        if isinstance(source, RevRuntimeV1File)
        else dict(source)
    )
    dependency_values = [
        dependency.to_dict()
        if isinstance(dependency, RevRuntimeV1File)
        else dict(dependency)
        for dependency in dependencies
    ]
    dependency_values.sort(key=lambda item: str(item.get("path", "")))
    return RevRuntimeV1Spec.from_mapping(
        {
            "argv": list(argv),
            "dependencies": dependency_values,
            "format": format,
            "options": {
                "architecture": architecture,
                "main_class": main_class,
                "qemu_ld_prefix": qemu_ld_prefix,
                "wasm_entrypoint": wasm_entrypoint,
                "working_directory": working_directory,
            },
            "protocol": REV_RUNTIME_V1_PROTOCOL,
            "runtime": runtime,
            "schema_version": REV_RUNTIME_V1_SCHEMA_VERSION,
            "source": source_value,
        }
    )


__all__ = [
    "REV_RUNTIME_V1_FORMATS",
    "REV_RUNTIME_V1_MAX_ARGV",
    "REV_RUNTIME_V1_MAX_DEPENDENCIES",
    "REV_RUNTIME_V1_MAX_DOCUMENT_BYTES",
    "REV_RUNTIME_V1_MAX_FILE_BYTES",
    "REV_RUNTIME_V1_MAX_TOTAL_FILE_BYTES",
    "REV_RUNTIME_V1_PROTOCOL",
    "REV_RUNTIME_V1_QEMU_ARCHITECTURES",
    "REV_RUNTIME_V1_RUNTIMES",
    "REV_RUNTIME_V1_SCHEMA_VERSION",
    "RevRuntimeV1Error",
    "RevRuntimeV1File",
    "RevRuntimeV1Options",
    "RevRuntimeV1Spec",
    "build_rev_runtime_v1_spec",
    "canonical_json_bytes",
]
