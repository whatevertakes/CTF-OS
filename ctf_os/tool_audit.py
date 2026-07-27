"""Offline pin contracts and optional official-upstream version audit."""

from __future__ import annotations

import json
import re
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

_CONTRACTS = (
    ("aflplusplus", "sandbox/install/pwn-fuzzing.sh", r"^AFLPP_VERSION=(.+)$"),
    ("afl_frida_gum", "sandbox/install/pwn-fuzzing.sh", r"^FRIDA_GUM_VERSION=(.+)$"),
    ("aflnet", "sandbox/install/pwn-network-fuzzing.sh", r"^AFLNET_COMMIT=(.+)$"),
    ("stateafl", "sandbox/install/pwn-network-fuzzing.sh", r"^STATEAFL_COMMIT=(.+)$"),
    ("atheris", "sandbox/install/pwn-language-fuzzing.sh", r"^ATHERIS_VERSION=(.+)$"),
    ("cargo-fuzz", "sandbox/install/pwn-language-fuzzing.sh", r"^CARGO_FUZZ_VERSION=(.+)$"),
    ("libfuzzer-sys", "sandbox/install/pwn-language-fuzzing.sh", r"^LIBFUZZER_SYS_VERSION=(.+)$"),
    ("go", "sandbox/install/pwn-advanced-fuzzing.sh", r"^GO_VERSION=(.+)$"),
    ("syzkaller", "sandbox/install/pwn-advanced-fuzzing.sh", r"^SYZKALLER_COMMIT=(.+)$"),
    ("honggfuzz", "sandbox/install/pwn-advanced-fuzzing.sh", r"^HONGGFUZZ_COMMIT=(.+)$"),
    ("radamsa", "sandbox/install/pwn-advanced-fuzzing.sh", r"^RADAMSA_COMMIT=(.+)$"),
    ("libafl", "sandbox/install/pwn-libafl.sh", r"^LIBAFL_VERSION=(.+)$"),
    ("ffuf", "sandbox/install/web.sh", r"^FFUF_VERSION=(.+)$"),
    ("nuclei", "sandbox/install/web.sh", r"^NUCLEI_VERSION=(.+)$"),
    ("dalfox", "sandbox/install/web.sh", r"^DALFOX_VERSION=(.+)$"),
    ("katana", "sandbox/install/web.sh", r"^KATANA_VERSION=(.+)$"),
    ("httpx-pd", "sandbox/install/web.sh", r"^HTTPX_PD_VERSION=(.+)$"),
    ("feroxbuster", "sandbox/install/web.sh", r"^FEROXBUSTER_VERSION=(.+)$"),
    ("grpcurl", "sandbox/install/web.sh", r"^GRPCURL_VERSION=(.+)$"),
    ("restler", "sandbox/install/restler-builder.sh", r"^RESTLER_COMMIT=(.+)$"),
    ("fuzzilli", "sandbox/install/fuzzilli-builder.sh", r"^FUZZILLI_COMMIT=(.+)$"),
    (
        "fuzzilli_jerryscript",
        "sandbox/install/fuzzilli-jerryscript-builder.sh",
        r"^JERRYSCRIPT_COMMIT=(.+)$",
    ),
    ("radare2", "sandbox/install/rev.sh", r"^RADARE2_VERSION=(.+)$"),
    ("jadx", "sandbox/install/rev.sh", r"^JADX_VERSION=(.+)$"),
    ("apktool", "sandbox/install/rev.sh", r"^APKTOOL_VERSION=(.+)$"),
    ("upx", "sandbox/install/rev.sh", r"^UPX_VERSION=(.+)$"),
    ("wasmtime", "sandbox/install/rev.sh", r"^WASMTIME_VERSION=(.+)$"),
    ("bulk_extractor", "sandbox/install/forensic.sh", r"^BULK_EXTRACTOR_VERSION=(.+)$"),
    ("kubectl", "sandbox/install/cloud.sh", r"^KUBECTL_VERSION=(.+)$"),
    ("helm", "sandbox/install/cloud.sh", r"^HELM_VERSION=(.+)$"),
    ("terraform", "sandbox/install/cloud.sh", r"^TERRAFORM_VERSION=(.+)$"),
    ("opentofu", "sandbox/install/cloud.sh", r"^TOFU_VERSION=(.+)$"),
    ("oras", "sandbox/install/cloud.sh", r"^ORAS_VERSION=(.+)$"),
    ("cosign", "sandbox/install/cloud.sh", r"^COSIGN_VERSION=(.+)$"),
    ("trivy", "sandbox/install/cloud.sh", r"^TRIVY_VERSION=(.+)$"),
    ("syft", "sandbox/install/cloud.sh", r"^SYFT_VERSION=(.+)$"),
    ("grype", "sandbox/install/cloud.sh", r"^GRYPE_VERSION=(.+)$"),
    ("opa", "sandbox/install/cloud.sh", r"^OPA_VERSION=(.+)$"),
    ("conftest", "sandbox/install/cloud.sh", r"^CONFTEST_VERSION=(.+)$"),
    ("kustomize", "sandbox/install/cloud.sh", r"^KUSTOMIZE_VERSION=(.+)$"),
    ("yq", "sandbox/install/cloud.sh", r"^YQ_VERSION=(.+)$"),
)

_UPSTREAM = {
    "aflplusplus": ("github_release", "AFLplusplus/AFLplusplus"),
    "libafl": ("github_release", "AFLplusplus/LibAFL"),
    "nuclei": ("github_release", "projectdiscovery/nuclei"),
    "dalfox": ("github_release", "hahwul/dalfox"),
    "katana": ("github_release", "projectdiscovery/katana"),
    "httpx-pd": ("github_release", "projectdiscovery/httpx"),
    "feroxbuster": ("github_release", "epi052/feroxbuster"),
    "grpcurl": ("github_release", "fullstorydev/grpcurl"),
    "radare2": ("github_release", "radareorg/radare2"),
    "jadx": ("github_release", "skylot/jadx"),
    "apktool": ("github_release", "iBotPeaches/Apktool"),
    "upx": ("github_release", "upx/upx"),
    "wasmtime": ("github_release", "bytecodealliance/wasmtime"),
    "bulk_extractor": ("github_release", "simsong/bulk_extractor"),
    "helm": ("github_release", "helm/helm"),
    "opentofu": ("github_release", "opentofu/opentofu"),
    "oras": ("github_release", "oras-project/oras"),
    "cosign": ("github_release", "sigstore/cosign"),
    "trivy": ("github_release", "aquasecurity/trivy"),
    "syft": ("github_release", "anchore/syft"),
    "grype": ("github_release", "anchore/grype"),
    "opa": ("github_release", "open-policy-agent/opa"),
    "conftest": ("github_release", "open-policy-agent/conftest"),
    "kustomize": ("github_release", "kubernetes-sigs/kustomize"),
    "yq": ("github_release", "mikefarah/yq"),
    "syzkaller": ("github_commit", "google/syzkaller"),
    "honggfuzz": ("github_commit", "google/honggfuzz"),
    "restler": ("github_commit", "microsoft/restler-fuzzer"),
    "fuzzilli": ("github_commit", "googleprojectzero/fuzzilli"),
}


def _load_lock(path: Path) -> tuple[dict[str, str], list[str]]:
    values: dict[str, str] = {}
    errors: list[str] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            errors.append(f"{path}:{number}: expected key=value")
            continue
        key, value = line.split("=", 1)
        if key in values:
            errors.append(f"{path}:{number}: duplicate key {key}")
        values[key] = value
        if key.endswith("_sha256") and not re.fullmatch(r"[0-9a-f]{64}", value):
            errors.append(f"{path}:{number}: invalid SHA-256 for {key}")
    return values, errors


def _official_json(
    url: str,
    *,
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> Any:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "ctf-os-tool-audit"},
    )
    with opener(request, timeout=20) as response:
        return json.load(response)


def run_tool_audit(
    repo: Path,
    *,
    check_upstream: bool = False,
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> dict[str, Any]:
    lock_path = repo / "sandbox" / "tool-versions.lock"
    lock, errors = _load_lock(lock_path)
    contracts: list[dict[str, Any]] = []
    for key, relative, pattern in _CONTRACTS:
        source = repo / relative
        match = re.search(pattern, source.read_text(encoding="utf-8"), re.MULTILINE)
        source_value = match.group(1) if match else None
        lock_value = lock.get(key)
        matched = source_value is not None and source_value == lock_value
        contracts.append({
            "key": key,
            "lock": lock_value,
            "source": relative,
            "source_value": source_value,
            "matched": matched,
        })
        if not matched:
            errors.append(
                f"pin contract mismatch for {key}: lock={lock_value!r} source={source_value!r}"
            )

    upstream: list[dict[str, Any]] = []
    if check_upstream:
        for key, (provider, name) in _UPSTREAM.items():
            pinned = lock.get(key)
            try:
                if provider == "github_release":
                    payload = _official_json(
                        f"https://api.github.com/repos/{name}/releases/latest",
                        opener=opener,
                    )
                    latest = str(payload["tag_name"])
                    for prefix in ("kustomize/v", "v"):
                        if latest.startswith(prefix):
                            latest = latest[len(prefix):]
                            break
                else:
                    payload = _official_json(
                        f"https://api.github.com/repos/{name}/commits?per_page=1",
                        opener=opener,
                    )
                    latest = str(payload[0]["sha"])
            except (OSError, ValueError, KeyError, IndexError) as exc:
                detail = f"{type(exc).__name__}: {exc}"
                upstream.append({
                    "key": key,
                    "provider": provider,
                    "name": name,
                    "pinned": pinned,
                    "latest": None,
                    "current": None,
                    "error": detail,
                })
                errors.append(f"upstream check failed for {key}: {detail}")
                continue
            current = pinned == latest
            upstream.append({
                "key": key,
                "provider": provider,
                "name": name,
                "pinned": pinned,
                "latest": latest,
                "current": current,
            })
            if not current:
                errors.append(f"upstream drift for {key}: pinned={pinned} latest={latest}")

    return {
        "ok": not errors,
        "lock": str(lock_path.relative_to(repo)),
        "lock_entries": len(lock),
        "sha256_entries": sum(key.endswith("_sha256") for key in lock),
        "contracts": contracts,
        "upstream_checked": check_upstream,
        "upstream": upstream,
        "compatibility_exceptions": {
            "atheris": "3.1.0 has no CPython 3.11 artifact; pinned 3.0.0",
            "angr": "9.2.213 is the newest Python 3.11-compatible release",
            "mitmproxy": "11.0.2 is the newest Python 3.11-compatible release",
            "fuzzilli_jerryscript": (
                "Pinned to the revision declared by the selected Fuzzilli "
                "Targets/Jerryscript/REVISION so its integration patch applies"
            ),
        },
        "errors": errors,
    }
