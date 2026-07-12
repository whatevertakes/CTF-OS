"""Evidence-backed hierarchical CTF problem classification."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import re
from typing import Iterable, Mapping


@dataclass(frozen=True, slots=True)
class ProblemProfile:
    category: str
    subtype: str
    variant: str = "unknown"
    platform: str = "unknown"
    architecture: str = "unknown"
    constraints: tuple[str, ...] = ()
    confidence: float = 0.0
    evidence: tuple[Mapping[str, object], ...] = ()
    candidate_strategies: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()
    unresolved_questions: tuple[str, ...] = ()
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError(f"unsupported problem profile version {self.schema_version}")
        if not 0 <= self.confidence <= 1:
            raise ValueError("profile confidence must be in [0, 1]")

    def updated(self, evidence: Iterable[Mapping[str, object]], *, classifier: "ProblemClassifier") -> "ProblemProfile":
        return classifier.classify(self.category, (*self.evidence, *tuple(evidence)), previous=self)


@dataclass(frozen=True, slots=True)
class _Rule:
    category: str
    subtype: str
    terms: tuple[str, ...]
    strategies: tuple[str, ...]
    capabilities: tuple[str, ...]
    platform: str = "unknown"


_RULES = (
    _Rule("pwn", "heap.glibc", ("heap", "glibc", "tcache", "fastbin", "unsorted"), ("fast_recon", "dynamic_analysis", "exploit_build"), ("gdb", "pwntools", "patchelf"), "linux"),
    _Rule("pwn", "format_string", ("format string", "%p", "%n", "printf"), ("fast_recon", "dynamic_analysis", "exploit_build"), ("checksec", "gdb", "pwntools"), "linux"),
    _Rule("pwn", "rop", ("rop", "nx enabled", "return oriented"), ("fast_recon", "exploit_build"), ("ROPgadget", "pwntools"), "linux"),
    _Rule("pwn", "stack_overflow", ("stack overflow", "gets(", "strcpy(", "buffer overflow"), ("fast_recon", "dynamic_analysis", "exploit_build"), ("gdb", "pwntools"), "linux"),
    _Rule("pwn", "shellcode", ("shellcode", "executable stack"), ("dynamic_analysis", "exploit_build"), ("gdb", "pwntools"), "linux"),
    _Rule("pwn", "heap", ("heap corruption", "use after free", "double free"), ("fast_recon", "dynamic_analysis", "exploit_build"), ("gdb", "pwntools"), "linux"),
    _Rule("pwn", "heap.custom_allocator", ("custom allocator", "custom heap", "arena implementation"), ("deep_analysis", "dynamic_analysis", "exploit_build"), ("gdb", "pwntools"), "linux"),
    _Rule("pwn", "seccomp", ("seccomp", "sandbox", "syscall filter"), ("fast_recon", "dynamic_analysis", "exploit_build"), ("seccomp-tools", "gdb"), "linux"),
    _Rule("pwn", "race_condition", ("race condition", "toctou", "concurrent"), ("protocol_replay", "dynamic_analysis", "exploit_build"), ("python", "strace"), "linux"),
    _Rule("pwn", "kernel", ("kernel", "ko module", "initramfs", "qemu"), ("artifact_recovery", "dynamic_analysis", "exploit_build"), ("gdb", "qemu"), "linux"),
    _Rule("pwn", "sandbox_escape", ("sandbox escape", "jail escape", "namespace escape"), ("fast_recon", "dynamic_analysis", "exploit_build"), ("strace", "gdb"), "linux"),
    _Rule("pwn", "windows", ("pe32", ".exe", "windows pwn"), ("windows_analysis", "dynamic_analysis", "exploit_build"), ("wine", "pefile"), "windows"),
    _Rule("pwn", "protocol_state_machine", ("state machine", "protocol", "handshake"), ("protocol_replay", "exploit_build"), ("python", "socat")),
    _Rule("web", "ssrf", ("ssrf", "metadata endpoint", "url parameter", "internal endpoint"), ("protocol_replay", "browser_automation"), ("curl", "python")),
    _Rule("web", "request_smuggling", ("request smuggling", "cl.te", "te.cl", "desync", "content-length", "transfer-encoding"), ("protocol_replay",), ("curl", "python", "socat")),
    _Rule("web", "jwt", ("jwt", "jsonwebtoken", "jwks", "jku", "alg:none"), ("protocol_replay", "browser_automation"), ("python", "curl")),
    _Rule("web", "sql_injection", ("sql injection", "select ", "sqlmap"), ("protocol_replay",), ("sqlmap", "curl")),
    _Rule("web", "deserialization", ("deserialization", "pickle", "objectinputstream", "unserialize"), ("fast_recon", "protocol_replay"), ("python", "curl")),
    _Rule("web", "cache_poisoning", ("cache poisoning", "cache key", "x-forwarded-host"), ("protocol_replay",), ("curl", "python")),
    _Rule("web", "oauth_oidc", ("oauth", "oidc", "redirect_uri", "authorization code"), ("browser_automation", "protocol_replay"), ("playwright", "curl")),
    _Rule("web", "websocket", ("websocket", "ws://", "wss://"), ("protocol_replay", "browser_automation"), ("python", "chromium")),
    _Rule("web", "ssti", ("ssti", "template injection", "jinja", "freemarker"), ("protocol_replay",), ("curl", "python")),
    _Rule("web", "xxe", ("xxe", "external entity", "doctype"), ("protocol_replay",), ("curl", "python")),
    _Rule("web", "path_traversal", ("path traversal", "file inclusion", "../", "lfi"), ("protocol_replay",), ("curl", "python")),
    _Rule("web", "auth_logic", ("authorization logic", "authentication bypass", "idor", "broken access"), ("protocol_replay", "browser_automation"), ("curl", "playwright")),
    _Rule("web", "race_condition", ("race condition", "double spend", "concurrent request"), ("protocol_replay",), ("python", "curl")),
    _Rule("web", "browser_client", ("client-side", "dom xss", "postmessage", "service worker"), ("browser_automation",), ("playwright", "chromium")),
    _Rule("web", "graphql", ("graphql", "introspection", "gql"), ("protocol_replay", "browser_automation"), ("curl", "python")),
    _Rule("web", "upload_parser_confusion", ("upload", "multipart", "parser confusion", "content-type"), ("protocol_replay",), ("curl", "file")),
    _Rule("rev", "android_apk", ("androidmanifest", ".apk", "dalvik", "apk"), ("mobile_analysis", "deep_analysis"), ("jadx", "apktool"), "android"),
    _Rule("rev", "windows_pe", ("pe32", ".exe", ".dll"), ("windows_analysis", "deep_analysis"), ("wine", "pefile"), "windows"),
    _Rule("rev", "native_elf", ("elf", "linux executable"), ("fast_recon", "deep_analysis", "dynamic_analysis"), ("readelf", "gdb"), "linux"),
    _Rule("rev", "packed_obfuscated", ("packed", "obfuscated", "upx", "high entropy"), ("artifact_recovery", "deep_analysis", "dynamic_analysis"), ("file", "r2")),
    _Rule("rev", "dotnet", (".net", "clr", "msil", "dnspy"), ("windows_analysis", "deep_analysis"), ("dotnet", "pefile"), "windows"),
    _Rule("rev", "java_jar", ("java", "jar", "class file"), ("artifact_recovery", "deep_analysis"), ("java", "javap"), "java"),
    _Rule("rev", "bytecode_vm", ("bytecode", "custom vm", "virtual machine opcode"), ("deep_analysis", "symbolic_math"), ("python", "z3")),
    _Rule("rev", "anti_debug", ("anti-debug", "ptrace", "timing check"), ("dynamic_analysis", "deep_analysis"), ("gdb", "strace")),
    _Rule("rev", "symbolic_execution", ("symbolic", "constraint", "angr"), ("symbolic_math", "deep_analysis"), ("z3", "angr")),
    _Rule("rev", "firmware_embedded", ("firmware", "embedded", "squashfs", "mips"), ("artifact_recovery", "deep_analysis"), ("binwalk", "file"), "embedded"),
    _Rule("crypto", "modular_arithmetic", ("modular arithmetic", "congruence", "modulo"), ("symbolic_math",), ("python", "sage")),
    _Rule("crypto", "rsa", ("rsa", "modulus", "public exponent", "ciphertext"), ("symbolic_math",), ("python", "sage")),
    _Rule("crypto", "lattice", ("lattice", "lwe", "lll", "small roots"), ("symbolic_math",), ("sage", "fpylll")),
    _Rule("crypto", "prng", ("prng", "random seed", "mersenne"), ("symbolic_math",), ("python", "z3")),
    _Rule("crypto", "ecc", ("elliptic curve", "ecc", "ecdsa"), ("symbolic_math",), ("sage", "python")),
    _Rule("crypto", "hash_mac_misuse", ("hash misuse", "length extension", "mac misuse", "hmac"), ("symbolic_math", "protocol_replay"), ("python",)),
    _Rule("crypto", "padding_oracle", ("padding oracle", "pkcs7", "oracle"), ("protocol_replay", "symbolic_math"), ("python", "curl")),
    _Rule("crypto", "custom_cipher", ("custom cipher", "homebrew crypto", "substitution"), ("symbolic_math", "deep_analysis"), ("python", "z3")),
    _Rule("crypto", "protocol_crypto", ("crypto protocol", "handshake", "key exchange"), ("protocol_replay", "symbolic_math"), ("python", "tshark")),
    _Rule("crypto", "constraint_solving", ("constraint", "z3", "sat"), ("symbolic_math",), ("z3", "python")),
    _Rule("forensics", "pcap", ("pcap", "packet capture", "wireshark"), ("protocol_replay", "artifact_recovery"), ("tshark",)),
    _Rule("forensics", "disk_image", ("disk image", "filesystem image", ".dd", ".img"), ("artifact_recovery",), ("sleuthkit", "foremost")),
    _Rule("forensics", "archive_polyglot", ("archive", "polyglot", "zip"), ("artifact_recovery",), ("file", "unzip")),
    _Rule("forensics", "memory_dump", ("memory dump", "volatility", "ram image"), ("artifact_recovery",), ("volatility3",)),
    _Rule("forensics", "document_media_stego", ("steganography", "document", "image", "media"), ("artifact_recovery",), ("exiftool", "binwalk")),
    _Rule("forensics", "log_timeline", ("log", "timeline", "event log"), ("artifact_recovery",), ("python", "jq")),
    _Rule("forensics", "firmware", ("firmware", "squashfs", "rom image"), ("artifact_recovery",), ("binwalk", "file")),
    _Rule("forensics", "mobile_artifact", ("mobile artifact", "android backup", "ios backup"), ("mobile_analysis", "artifact_recovery"), ("jadx", "sqlite3")),
    _Rule("forensics", "cloud_artifact", ("cloud artifact", "cloudtrail", "audit log"), ("cloud_analysis", "artifact_recovery"), ("jq", "python")),
    _Rule("cloud", "configuration", ("terraform", "iam", "cloudformation", "kubernetes", "azure", "gcp", "aws"), ("cloud_analysis",), ("terraform", "jq"), "cloud"),
    _Rule("mobile", "android_static", ("apk", "android", "manifest"), ("mobile_analysis",), ("jadx", "apktool"), "android"),
    _Rule("password", "hash_cracking", ("hashcat", "john", "password hash", "bcrypt", "sha512crypt"), ("password_cracking",), ("hashcat_or_john",)),
    _Rule("osint", "web_collection", ("osint", "source url", "geolocation"), ("osint_collection", "browser_automation"), ("curl", "exiftool")),
    _Rule("hardware", "embedded", ("hardware", "uart", "jtag", "firmware"), ("artifact_recovery", "deep_analysis"), ("binwalk", "file"), "embedded"),
    _Rule("misc", "protocol", ("protocol", "handshake", "state machine"), ("protocol_replay",), ("python", "socat")),
)


class ProblemClassifier:
    """Deterministic classifier whose evidence can be updated during a solve."""

    def classify(
        self, category: str, evidence: Iterable[Mapping[str, object] | str], *,
        previous: ProblemProfile | None = None,
    ) -> ProblemProfile:
        category = category.strip().casefold()
        category = {"reversing": "rev", "reverse": "rev", "forensic": "forensics"}.get(category, category)
        normalized: list[Mapping[str, object]] = []
        corpus: list[str] = []
        for item in evidence:
            record = {"kind": "text", "value": item} if isinstance(item, str) else dict(item)
            normalized.append(record)
            corpus.append(" ".join(str(value) for value in record.values()).casefold())
        text = "\n".join(corpus)
        candidates: list[tuple[float, _Rule, tuple[str, ...]]] = []
        for rule in _RULES:
            if rule.category != category and not (category == "misc" and rule.category in {"mobile", "password", "osint"}):
                continue
            matches = tuple(term for term in rule.terms if term in text)
            if matches:
                candidates.append((min(0.98, 0.45 + 0.13 * len(matches)), rule, matches))
        if candidates:
            score, rule, matches = max(candidates, key=lambda item: (item[0], len(item[2]), item[1].subtype))
            subtype, strategies, capabilities, platform = rule.subtype, rule.strategies, rule.capabilities, rule.platform
            evidence_out = tuple(normalized) + ({"kind": "classification_terms", "value": list(matches), "rule": f"{rule.category}.{rule.subtype}"},)
        else:
            score = 0.2 if normalized else 0.0
            subtype, strategies, capabilities, platform = "unknown", ("fast_recon",), (), "unknown"
            evidence_out = tuple(normalized)
        architecture = _architecture(text)
        if previous and previous.subtype == subtype:
            score = min(0.99, max(score, previous.confidence) + 0.03)
        questions = () if subtype != "unknown" else ("Which observable primitive or file/protocol signature distinguishes the subtype?",)
        return ProblemProfile(category, subtype, platform=platform, architecture=architecture,
                              confidence=score, evidence=evidence_out,
                              candidate_strategies=strategies, required_capabilities=capabilities,
                              unresolved_questions=questions)


def _architecture(text: str) -> str:
    for pattern, value in ((r"\b(?:x86-64|amd64|x86_64)\b", "x86_64"), (r"\bi[3-6]86\b", "x86"),
                           (r"\baarch64\b", "aarch64"), (r"\barm(?:v7)?\b", "arm"),
                           (r"\bmips(?:el)?\b", "mips")):
        if re.search(pattern, text):
            return value
    return "unknown"
