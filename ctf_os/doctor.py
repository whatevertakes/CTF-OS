"""Pre-contest infrastructure and immutable image capability checks."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import tomllib
from typing import Any

from .delegation import DelegationError, load_templates
from .model_routing import (
    PROFILE_POLICIES,
    ROUTING_PROFILES,
    RoutingError,
    build_native_delegation_packet,
    build_routing_contract,
)
from .resources.scheduler import detect_gpus
from .sandbox.runtime import SandboxSpec, cleanup, create, execute
from .timeouts import TimeoutProfileError, load_timeout_profiles


PROFILES = ("base", "pwn", "web", "rev", "crypto", "forensic", "misc", "osint", "ai", "cloud")
IMAGES = tuple(f"ctf-os-sandbox:{name}" for name in PROFILES)

_COMMON_ENV = (
    "export HOME=/work/home XDG_CONFIG_HOME=/work/home/.config "
    "XDG_CACHE_HOME=/work/home/.cache XDG_RUNTIME_DIR=/work/runtime TMPDIR=/work/tmp "
    "AWS_SHARED_CREDENTIALS_FILE=/work/credentials/aws AWS_CONFIG_FILE=/work/credentials/aws-config "
    "AZURE_CONFIG_DIR=/work/credentials/azure CLOUDSDK_CONFIG=/work/credentials/gcloud "
    "KUBECONFIG=/work/credentials/kubeconfig; "
    "mkdir -p \"$HOME\" \"$XDG_CONFIG_HOME\" \"$XDG_CACHE_HOME\" "
    "\"$XDG_RUNTIME_DIR\" \"$TMPDIR\" /work/credentials; "
)

PROFILE_PROBES: dict[str, str] = {
    "base": """
command -v python3; command -v jq; command -v rg; command -v objdump; command -v strings; command -v readelf; command -v nmap
python3 -c 'import requests,httpx,bs4,lxml,yaml,rich,numpy,scipy,PIL,networkx,sympy,z3,Crypto,cryptography,capstone,unicorn'
python3 --version; jq --version; rg --version; objdump --version; nmap --version
""",
    "pwn": """
for c in gdb gdb-multiarch qemu-aarch64 qemu-arm qemu-mips qemu-mipsel qemu-riscv64 qemu-system-x86_64 qemu-system-aarch64 patchelf checksec ROPgadget ropper one_gadget pwninit seccomp-tools musl-gcc aarch64-linux-gnu-gcc arm-linux-gnueabihf-gcc mipsel-linux-gnu-gcc riscv64-linux-gnu-gcc; do command -v "$c"; done
python3 -c 'import pwn,angr,unicorn,capstone,keystone,z3'
gdb --version; patchelf --version; checksec --help >/dev/null; ROPgadget --version; ropper --version; one_gadget --version; pwninit --version; seccomp-tools --version; musl-gcc --version
qemu-aarch64 --version; qemu-mips --version; qemu-system-x86_64 --version
/usr/local/bin/ctf-os-binary-runtime-smoke
""",
    "web": """
for c in node npm npx corepack php sqlite3 redis-cli psql mysql chromium chromedriver ffuf; do command -v "$c"; done
node -e 'if (Number(process.versions.node.split(".")[0]) < 18) process.exit(1)'
python3 -c 'import flask,fastapi,uvicorn,jwt,requests,httpx,websockets,dns,playwright'
node --version; npm --version; php --version; sqlite3 --version
ffuf -V
/usr/local/bin/ctf-os-web-runtime-smoke
""",
    "rev": """
(command -v r2 || command -v rizin)
for c in gdb gdb-multiarch jadx apktool wasm-objdump upx wasmtime mono qemu-aarch64 qemu-arm qemu-mips qemu-mipsel qemu-riscv64 qemu-system-x86_64 qemu-system-aarch64 qemu-system-riscv64 qemu-img aarch64-linux-gnu-gcc arm-linux-gnueabihf-gcc mipsel-linux-gnu-gcc riscv64-linux-gnu-gcc; do command -v "$c"; done
python3 -c 'import angr,unicorn,capstone,keystone,lief,pefile,elftools,pyopencl'
r2 -v; jadx --version; apktool --version; wasm-objdump --version; upx --version; wasmtime --version
/usr/local/bin/ctf-os-binary-runtime-smoke
/usr/local/bin/ctf-os-system-qemu-smoke
""",
    "crypto": """
for c in sage RsaCtfTool cado-nfs gp gap maxima hashcat; do command -v "$c"; done
python3 -c 'import z3,gmpy2,Crypto,fpylll,cysignals,sympy,cryptography,ecdsa'
sage -c 'assert 2^10 == 1024; assert GF(7)(3)^2 == 2'
RsaCtfTool --help >/dev/null; cado-nfs --help >/dev/null; gp --version; gap --version; maxima --version; hashcat --version
""",
    "forensic": """
for c in vol mmls fls icat foremost exiftool binwalk tshark tcpdump testdisk photorec dcfldd steghide stegseek zsteg convert tesseract pngcheck ffmpeg sox; do command -v "$c"; done
python3 -c 'import volatility3,scapy,pyshark,oletools,pdfminer,magic,PIL,numpy,scipy,capstone'
vol -h >/dev/null; mmls -V; tshark --version; stegseek --version; zsteg -h >/dev/null; ffmpeg -version; sox --version
""",
    "misc": """
for c in ffmpeg sox convert tesseract tshark binwalk exiftool dot parallel podman zbarimg php lua perl node npm; do command -v "$c"; done
python3 -c 'import torch,sklearn,cv2,pandas,PIL,numpy,scipy,networkx,sympy,z3,scapy,qrcode; assert torch.tensor([2,3]).sum().item() == 5'
ffmpeg -version; sox --version; convert -version; tesseract --version
podman --storage-driver=vfs info --format '{{.Host.Security.Rootless}}' | grep -q true
tar -cf /work/rootfs.tar --files-from /dev/null
podman --storage-driver=vfs import /work/rootfs.tar localhost/ctf-os-smoke:local >/dev/null
podman --storage-driver=vfs image inspect localhost/ctf-os-smoke:local --format '{{.RepoTags}}' | grep -q ctf-os-smoke
""",
    "osint": """
for c in whois dig nslookup host traceroute chromium exiftool convert tesseract ffmpeg yt-dlp git-lfs pdftotext waybackurls; do command -v "$c"; done
python3 -c 'import requests,httpx,bs4,lxml,playwright,PIL,cv2,pandas,whois,dns,geopy,exifread,pdfminer'
chromium --headless --no-sandbox --disable-gpu --dump-dom 'data:text/html,<title>ctf-os</title>' | grep -q ctf-os
""",
    "ai": """
for c in protoc h5dump ncdump dot jupyter; do command -v "$c"; done
python3 - <<'PY'
import numpy as np, onnx, onnxruntime as ort, torch, torchvision
import sklearn, transformers, tokenizers, sentencepiece, safetensors, datasets, joblib, cv2, pandas
from onnx import TensorProto, helper
assert torch.version.cuda is not None
assert torch.tensor([2,3]).sum().item() == 5
node=helper.make_node('Identity',['x'],['y'])
graph=helper.make_graph([node],'smoke',[helper.make_tensor_value_info('x',TensorProto.FLOAT,[1])],[helper.make_tensor_value_info('y',TensorProto.FLOAT,[1])])
model=helper.make_model(graph,opset_imports=[helper.make_opsetid('',17)],ir_version=9)
session=ort.InferenceSession(model.SerializeToString(),providers=['CPUExecutionProvider'])
assert session.run(None,{'x':np.array([7],dtype=np.float32)})[0][0] == 7
PY
""",
    "cloud": """
for c in aws az gcloud kubectl helm terraform tofu podman skopeo oras cosign trivy syft grype kustomize opa conftest checkov semgrep; do command -v "$c"; done
aws --version; az version; gcloud --version; kubectl version --client=true; helm version --short; terraform version; tofu version
podman --version; skopeo --version; oras version; cosign version; trivy --version; syft version; grype version; opa version; conftest --version; checkov --version; semgrep --version
python3 -c 'import boto3,botocore,google.cloud.storage,google.auth,azure.identity,azure.storage.blob,kubernetes,yaml,requests,httpx,jinja2'
test "${AWS_SHARED_CREDENTIALS_FILE:-/work/credentials/aws}" = /work/credentials/aws
test ! -e "$HOME/.aws/credentials"; test ! -e "$HOME/.azure"; test ! -e "$HOME/.config/gcloud"; test ! -e "$HOME/.kube/config"
""",
}

GPU_AI_TORCH_PROBE = """
import torch
assert torch.version.cuda is not None
assert torch.cuda.is_available()
x = torch.ones(1024, device="cuda")
y = x.sum()
torch.cuda.synchronize()
assert y.item() == 1024
print(torch.version.cuda, torch.cuda.get_device_name(0))
"""

GPU_AI_ONNX_PROBE = """
import numpy as np
import torch
import onnxruntime as ort
from onnx import TensorProto, helper
assert "CUDAExecutionProvider" in ort.get_available_providers()
node = helper.make_node("Add", ["x", "x"], ["y"])
graph = helper.make_graph(
    [node], "gpu-smoke",
    [helper.make_tensor_value_info("x", TensorProto.FLOAT, [4])],
    [helper.make_tensor_value_info("y", TensorProto.FLOAT, [4])],
)
model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)], ir_version=9)
session = ort.InferenceSession(
    model.SerializeToString(), providers=["CUDAExecutionProvider", "CPUExecutionProvider"],
)
assert session.get_providers()[0] == "CUDAExecutionProvider"
result = session.run(None, {"x": np.ones(4, dtype=np.float32)})[0]
assert result.tolist() == [2.0, 2.0, 2.0, 2.0]
print(session.get_providers())
"""

GPU_REV_PROBE = '''
import numpy as np
import pyopencl as cl
devices = [
    device
    for platform in cl.get_platforms()
    for device in platform.get_devices(device_type=cl.device_type.GPU)
    if "NVIDIA" in (device.vendor + " " + device.name).upper()
]
assert devices, "no NVIDIA OpenCL GPU"
context = cl.Context([devices[0]])
queue = cl.CommandQueue(context)
values = np.arange(64, dtype=np.uint32)
output = np.empty_like(values)
source = """
__kernel void candidate_check(__global const uint *input, __global uint *output) {
    size_t i = get_global_id(0);
    output[i] = input[i] * input[i] + 7;
}
"""
program = cl.Program(context, source).build()
flags = cl.mem_flags
input_buffer = cl.Buffer(context, flags.READ_ONLY | flags.COPY_HOST_PTR, hostbuf=values)
output_buffer = cl.Buffer(context, flags.WRITE_ONLY, output.nbytes)
program.candidate_check(queue, values.shape, None, input_buffer, output_buffer)
cl.enqueue_copy(queue, output, output_buffer).wait()
assert np.array_equal(output, values * values + 7)
print(devices[0].name)
'''


def _run(
    argv: list[str], timeout: int = 30, *, cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv, capture_output=True, text=True, check=False, timeout=timeout, cwd=cwd,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(argv, 127, "", str(exc))


def _image_probe(profile: str) -> subprocess.CompletedProcess[str]:
    command = _COMMON_ENV + PROFILE_PROBES[profile]
    argv = [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--security-opt", "no-new-privileges", "--cap-drop", "ALL", "--user", "1001:1001",
        "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=256m,mode=1777", "--tmpfs", "/work:rw,nosuid,nodev,size=1g,mode=1777",
        "--tmpfs", "/artifacts:rw,nosuid,nodev,size=64m,mode=1777",
    ]
    if profile in {"pwn", "rev"}:
        # Match the existing solve runtime contract. Docker's default seccomp
        # filter rejects i386 syscalls before the 32-bit execution probe runs.
        argv.extend([
            "--cap-add", "SYS_PTRACE", "--security-opt", "seccomp=unconfined",
            "--ulimit", "core=-1:-1",
        ])
    if profile in {"misc", "cloud"}:
        seccomp = Path(__file__).resolve().parents[1] / "sandbox" / "seccomp-rootless.json"
        argv.extend(["--security-opt", f"seccomp={seccomp}"])
    argv.extend(["--entrypoint", "sh", f"ctf-os-sandbox:{profile}", "-ec", command])
    return _run(argv, timeout=180)


def inspect_codex_routing_capabilities(
    repo: Path,
    *,
    run: Callable[..., subprocess.CompletedProcess[str]] = _run,
) -> dict[str, object]:
    """Inspect Codex routing conservatively without launching a model or child."""

    warnings: list[str] = []
    codex = shutil.which("codex")
    version: subprocess.CompletedProcess[str] | None = None
    native_delegation = "UNKNOWN"
    native_delegation_evidence: dict[str, object] = {
        "source": "installed Codex CLI features list",
        "detail": "Codex CLI binary not found",
    }
    catalog_result: subprocess.CompletedProcess[str] | None = None
    catalog: dict[str, set[str]] = {}
    catalog_observable = False
    model_catalog_evidence: dict[str, object] = {
        "source": "installed Codex CLI model catalog",
        "detail": "Codex CLI binary not found",
    }
    if codex:
        version = run([codex, "--version"], timeout=15)
        features = run([codex, "features", "list"], timeout=20)
        feature_line = next((
            line.strip() for line in features.stdout.splitlines()
            if line.split()[:1] == ["multi_agent"]
        ), None)
        if features.returncode != 0:
            native_detail = "features list command failed; multi_agent state not verified"
        elif feature_line is None:
            native_detail = "features list did not report multi_agent"
        elif feature_line.split()[-1:] == ["true"]:
            native_delegation = "SUPPORTED"
            native_detail = f"features list reported: {feature_line}"
        elif feature_line.split()[-1:] == ["false"]:
            native_delegation = "UNSUPPORTED"
            native_detail = f"features list reported: {feature_line}"
        else:
            native_detail = f"features list value was not understood: {feature_line}"
        native_delegation_evidence = {
            "source": "installed Codex CLI features list",
            "command": [codex, "features", "list"],
            "returncode": features.returncode,
            "multi_agent_line": feature_line,
            "detail": native_detail,
        }
        catalog_result = run([codex, "debug", "models"], timeout=30)

    if catalog_result is not None and catalog_result.returncode == 0:
        try:
            raw_catalog = json.loads(catalog_result.stdout)
            raw_models = raw_catalog.get("models")
            if not isinstance(raw_models, list):
                raise ValueError("model catalog models field is not a list")
            for item in raw_models:
                if not isinstance(item, Mapping) or not item.get("slug"):
                    continue
                catalog[str(item["slug"])] = {
                    str(level.get("effort")) for level in item.get("supported_reasoning_levels", [])
                    if isinstance(level, Mapping) and level.get("effort")
                }
            catalog_observable = True
            model_catalog_evidence = {
                "source": "installed Codex CLI model catalog",
                "command": [codex, "debug", "models"],
                "returncode": catalog_result.returncode,
                "models_observed": sorted(catalog),
            }
        except (json.JSONDecodeError, AttributeError, ValueError):
            warnings.append("Codex model catalog was malformed")
            model_catalog_evidence = {
                "source": "installed Codex CLI model catalog",
                "command": [codex, "debug", "models"],
                "returncode": catalog_result.returncode,
                "detail": "catalog output was malformed and cannot establish capability",
            }
    elif catalog_result is not None:
        warnings.append("Codex model catalog was unavailable")
        model_catalog_evidence = {
            "source": "installed Codex CLI model catalog",
            "command": [codex, "debug", "models"],
            "returncode": catalog_result.returncode,
            "detail": "catalog command failed",
        }
    else:
        warnings.append("Codex CLI binary not found")

    required_catalog_pairs = {
        (str(policy["model"]), str(reasoning))
        for policy in PROFILE_POLICIES.values()
        for reasoning in (
            policy.get("agent_profiles", {}).keys() or (policy["reasoning"],)
        )
    }
    missing_catalog_pairs = sorted(
        f"{model}/{reasoning}"
        for model, reasoning in required_catalog_pairs
        if reasoning not in catalog.get(model, set())
    ) if catalog_observable else []
    if not catalog_observable:
        model_catalog_status = "UNKNOWN"
    elif missing_catalog_pairs:
        model_catalog_status = "INVALID"
        warnings.append(
            "current model catalog is missing required routing combinations: "
            + ", ".join(missing_catalog_pairs)
        )
    else:
        model_catalog_status = "VALID"

    profile_results: dict[str, dict[str, object]] = {}
    locally_valid_profiles: list[str] = []
    configuration_invalid = False
    for routing_profile in sorted(ROUTING_PROFILES):
        policy = PROFILE_POLICIES[routing_profile]
        variants = policy.get("agent_profiles") or {
            str(policy["reasoning"]): str(policy["agent_profile"]),
        }
        variant_results: dict[str, dict[str, object]] = {}
        for reasoning, raw_name in variants.items():
            name = str(raw_name)
            path = repo / ".codex" / "agents" / f"{name}.toml"
            configuration_errors: list[str] = []
            catalog_errors: list[str] = []
            payload: Mapping[str, Any] = {}
            try:
                if path.is_symlink() or not path.is_file():
                    raise ValueError("profile file missing or unsafe")
                parsed = tomllib.loads(path.read_text(encoding="utf-8"))
                if not isinstance(parsed, Mapping):
                    raise ValueError("profile is not a TOML object")
                payload = parsed
            except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
                configuration_errors.append(str(exc))
            for field in ("name", "description", "developer_instructions"):
                if not str(payload.get(field) or "").strip():
                    configuration_errors.append(f"missing {field}")
            if payload.get("name") != name:
                configuration_errors.append("profile name mismatch")
            if payload.get("model") != policy["model"]:
                configuration_errors.append("model mapping mismatch")
            if payload.get("model_reasoning_effort") != reasoning:
                configuration_errors.append("reasoning mapping mismatch")
            if catalog_observable:
                efforts = catalog.get(str(policy["model"]), set())
                if not efforts:
                    catalog_errors.append("model identifier absent from current catalog")
                elif reasoning not in efforts:
                    catalog_errors.append("reasoning effort absent from current model catalog")
            errors = configuration_errors + catalog_errors
            variant_results[str(reasoning)] = {
                "custom_agent_profile": name, "path": str(path),
                "model": policy["model"], "reasoning": reasoning,
                "valid": not errors and catalog_observable,
                "configuration_errors": configuration_errors,
                "catalog_errors": catalog_errors,
                "errors": errors,
            }
        default = variant_results[str(policy["reasoning"])]
        local_valid = all(
            not bool(row["configuration_errors"]) for row in variant_results.values()
        )
        if not local_valid:
            configuration_invalid = True
        catalog_valid = catalog_observable and all(
            not bool(row["catalog_errors"]) for row in variant_results.values()
        )
        profile_results[routing_profile] = {
            "custom_agent_profile": default["custom_agent_profile"],
            "path": default["path"],
            "model": policy["model"], "reasoning": policy["reasoning"],
            "valid": local_valid and catalog_valid,
            "local_configuration_valid": local_valid,
            "catalog_valid": catalog_valid if catalog_observable else None,
            "errors": [
                error for row in variant_results.values() for error in row["errors"]
            ],
            "variants": variant_results,
        }
        if local_valid:
            locally_valid_profiles.append(routing_profile)

    if configuration_invalid or model_catalog_status == "INVALID":
        custom_agent_configuration = "INVALID"
    elif model_catalog_status == "VALID":
        custom_agent_configuration = "VALID"
    else:
        custom_agent_configuration = "UNKNOWN"
    if custom_agent_configuration == "INVALID":
        warnings.append("one or more CTF custom agent configurations are invalid")
    elif custom_agent_configuration == "UNKNOWN":
        warnings.append("custom agent configuration cannot be fully validated without the model catalog")

    packet_contract_errors: list[str] = []
    for routing_profile in sorted(ROUTING_PROFILES):
        policy = PROFILE_POLICIES[routing_profile]
        branch_evidence: dict[str, object] = {}
        if routing_profile == "MECHANICAL":
            branch_evidence = {
                "mechanical_only": True,
                "hypothesis": "deterministically extract and normalize fixed values",
            }
        elif routing_profile == "CONFIRMED_BOTTLENECK":
            branch_evidence = {
                "primitive_confirmed": True,
                "specific_blocker_present": True,
                "blocker_type": "MATH_CONSTRAINT",
                "xhigh_decisive_experiments": 1,
                "working_poc_present": False,
                "flag_path_present": False,
            }
        try:
            contract = build_routing_contract(
                routing_profile,
                routing_reason="doctor packet contract validation",
                routing_evidence=["doctor:local-contract"],
                branch_evidence=branch_evidence,
            )
            packet = build_native_delegation_packet(
                contract,
                task_name=f"doctor_{routing_profile.casefold()}",
                child_prompt={"doctor_probe": True},
            )
        except (KeyError, RoutingError, TypeError, ValueError) as exc:
            packet_contract_errors.append(f"{routing_profile}: builder failed: {exc}")
            continue
        spawn_args = packet.get("spawn_agent_args")
        routing_metadata = packet.get("routing_metadata")
        expected_agent = str(
            policy.get("agent_profiles", {}).get(
                str(policy["reasoning"]), policy["agent_profile"],
            )
        )
        prefix = f"{routing_profile}: "
        if packet.get("schema_version") != 2:
            packet_contract_errors.append(prefix + "schema_version is not 2")
        if not isinstance(routing_metadata, Mapping):
            packet_contract_errors.append(prefix + "routing_metadata is missing or not an object")
        if not isinstance(spawn_args, Mapping):
            packet_contract_errors.append(prefix + "spawn_agent_args is missing or not an object")
            continue
        expected_keys = {"task_name", "agent_type", "fork_turns", "message"}
        actual_keys = set(spawn_args)
        if actual_keys != expected_keys:
            packet_contract_errors.append(
                prefix + f"spawn_agent_args keys are {sorted(actual_keys)}, expected {sorted(expected_keys)}"
            )
        if spawn_args.get("fork_turns") != "none":
            packet_contract_errors.append(prefix + "fork_turns is not 'none'")
        if spawn_args.get("agent_type") != expected_agent:
            packet_contract_errors.append(
                prefix + f"agent_type does not select {expected_agent}"
            )
        message = spawn_args.get("message")
        if not isinstance(message, str):
            packet_contract_errors.append(prefix + "message is not a string")
            continue
        try:
            decoded_message = json.loads(message)
        except json.JSONDecodeError:
            packet_contract_errors.append(prefix + "message is not valid JSON")
            continue
        if not isinstance(decoded_message, Mapping):
            packet_contract_errors.append(prefix + "decoded message is not an object")
            continue
        for field in ("routing_contract", "routing_limits"):
            if not isinstance(decoded_message.get(field), Mapping):
                packet_contract_errors.append(prefix + f"decoded message lacks {field}")
    packet_contract = "INVALID" if packet_contract_errors else "VALID"
    packet_contract_evidence = {
        "source": "CTF-OS build_routing_contract and build_native_delegation_packet",
        "profiles_validated": sorted(ROUTING_PROFILES),
        "validation": (
            "schema v2, routing_metadata, exact spawn_agent_args keys, fork_turns none, "
            "profile agent_type, JSON message, routing_contract, and routing_limits"
        ),
        "runtime_acceptance_proven": False,
    }
    if packet_contract == "INVALID":
        warnings.append("CTF-OS native delegation packet contract is invalid")

    custom_agent_profile_selection = "UNKNOWN"
    custom_agent_selection_evidence = [
        "effective spawn_agent tool schema not observable without starting a runtime session",
        "effective project custom-agent registry not exposed by installed read-only CLI",
        "tracked TOML files establish configuration only, not effective runtime loading",
    ]
    if not codex:
        custom_agent_selection_evidence.insert(0, "Codex CLI binary not found")
    if native_delegation == "UNSUPPORTED":
        custom_agent_selection_evidence.insert(0, "multi_agent is explicitly disabled")

    if custom_agent_configuration == "INVALID" or model_catalog_status == "INVALID":
        model_override = "UNSUPPORTED"
        reasoning_override = "UNSUPPORTED"
    elif custom_agent_profile_selection == "SUPPORTED":
        model_override = "SUPPORTED"
        reasoning_override = "SUPPORTED"
    else:
        model_override = "UNKNOWN"
        reasoning_override = "UNKNOWN"
    if model_override == "UNSUPPORTED":
        override_evidence = (
            "custom-agent configuration or required model catalog combination is invalid"
        )
    elif model_override == "SUPPORTED":
        override_evidence = (
            "valid custom-agent configuration and catalog are bound to verified effective selection"
        )
    else:
        override_evidence = (
            "valid requested configuration/catalog do not prove effective custom-agent selection"
        )

    runtime_observation = "NOT_OBSERVABLE"
    runtime_identity_observation_evidence = [
        "child-specific model/reasoning observation surface not available",
        "generic ThreadStartResponse fields do not bind a spawned child to its actual model and reasoning effort",
        "no model or child session was launched by doctor",
    ]
    warnings.append("native custom-agent selection is not verified against the effective runtime")
    warnings.append("child-specific native model/reasoning identity is not observable")
    return {
        "codex_version": (
            version.stdout.strip() if version is not None and version.returncode == 0 else None
        ),
        "native_delegation": native_delegation,
        "native_delegation_evidence": native_delegation_evidence,
        "model_catalog_status": model_catalog_status,
        "model_catalog_evidence": model_catalog_evidence,
        "model_catalog_missing_combinations": missing_catalog_pairs,
        "packet_contract": packet_contract,
        "packet_contract_errors": packet_contract_errors,
        "packet_contract_evidence": packet_contract_evidence,
        "custom_agent_configuration": custom_agent_configuration,
        "custom_agent_configuration_evidence": {
            "profiles_checked": sorted(profile_results),
            "regular_non_symlink_toml_required": True,
            "catalog_cross_check": model_catalog_status,
        },
        "model_override": model_override,
        "model_override_evidence": override_evidence,
        "reasoning_override": reasoning_override,
        "reasoning_override_evidence": override_evidence,
        "direct_native_override": "UNKNOWN",
        "direct_native_override_evidence": (
            "effective spawn_agent tool schema is not exposed by the installed read-only CLI; "
            "direct model/reasoning arguments were not inferred"
        ),
        "custom_agent_profile_selection": custom_agent_profile_selection,
        "custom_agent_selection_evidence": custom_agent_selection_evidence,
        "override_transport": "PROJECT_CUSTOM_AGENT",
        "runtime_identity_observation": runtime_observation,
        "runtime_identity_observation_evidence": runtime_identity_observation_evidence,
        "max_reasoning": (
            "UNKNOWN" if not catalog_observable else
            "SUPPORTED" if "max" in catalog.get("gpt-5.6-sol", set()) else "UNSUPPORTED"
        ),
        "ultra_mode_observation": "NOT_OBSERVABLE",
        "valid_routing_profiles": (
            sorted(ROUTING_PROFILES) if custom_agent_configuration == "VALID" else []
        ),
        "supported_routing_profiles": (
            sorted(ROUTING_PROFILES) if custom_agent_profile_selection == "SUPPORTED" else []
        ),
        "catalog_valid_model_identifiers": sorted({
            str(PROFILE_POLICIES[profile]["model"])
            for profile in locally_valid_profiles
            if str(PROFILE_POLICIES[profile]["model"]) in catalog
        }),
        "supported_model_identifiers": (
            sorted({
                str(PROFILE_POLICIES[profile]["model"])
                for profile in ROUTING_PROFILES
            }) if custom_agent_profile_selection == "SUPPORTED" else []
        ),
        "custom_agent_profiles": profile_results,
        "warnings": warnings,
        "model_session_launched": False,
    }


def _codex_model_routing_check(model_routing: Mapping[str, object]) -> dict[str, object]:
    """Translate routing evidence into the doctor check's PASS/WARN/FAIL state."""

    required_supported = (
        "native_delegation",
        "custom_agent_profile_selection",
        "model_override",
        "reasoning_override",
        "runtime_identity_observation",
    )
    routing_supported = (
        model_routing.get("packet_contract") == "VALID"
        and model_routing.get("custom_agent_configuration") == "VALID"
        and all(model_routing.get(field) == "SUPPORTED" for field in required_supported)
    )
    failures: list[str] = []
    if model_routing.get("native_delegation") == "UNSUPPORTED":
        failures.append("native delegation is explicitly disabled")
    if model_routing.get("model_catalog_status") == "INVALID":
        failures.append("model catalog lacks a required model/reasoning combination")
    if model_routing.get("custom_agent_configuration") == "INVALID":
        failures.append("custom-agent configuration is invalid")
    if model_routing.get("packet_contract") == "INVALID":
        failures.append("packet contract is invalid")
    if (
        model_routing.get("model_override") == "UNSUPPORTED"
        or model_routing.get("reasoning_override") == "UNSUPPORTED"
    ) and not any("configuration" in item or "catalog" in item for item in failures):
        failures.append("model/reasoning override is explicitly unsupported")
    if routing_supported:
        return {
            "name": "codex-model-routing",
            "ok": True,
            "status": "PASS",
            "detail": "packet/config valid; native routing and child model/reasoning identity verified",
        }
    if failures:
        return {
            "name": "codex-model-routing",
            "ok": False,
            "status": "FAIL",
            "detail": "; ".join(failures),
        }

    uncertain: list[str] = []
    if model_routing.get("packet_contract") != "VALID":
        uncertain.append("packet contract not verified")
    if model_routing.get("model_catalog_status") != "VALID":
        uncertain.append("model catalog not verified")
    if model_routing.get("custom_agent_configuration") != "VALID":
        uncertain.append("custom-agent configuration not fully verified")
    if model_routing.get("native_delegation") != "SUPPORTED":
        uncertain.append("native delegation feature not verified")
    if model_routing.get("custom_agent_profile_selection") != "SUPPORTED":
        uncertain.append("native custom-agent selection not verified")
    if model_routing.get("model_override") != "SUPPORTED":
        uncertain.append("model override not verified")
    if model_routing.get("reasoning_override") != "SUPPORTED":
        uncertain.append("reasoning override not verified")
    if model_routing.get("runtime_identity_observation") != "SUPPORTED":
        uncertain.append("child model/reasoning identity not observable")
    confirmed: list[str] = []
    if (
        model_routing.get("packet_contract") == "VALID"
        and model_routing.get("custom_agent_configuration") == "VALID"
    ):
        confirmed.append("packet/config valid")
    return {
        "name": "codex-model-routing",
        "ok": True,
        "status": "WARN",
        "detail": "; ".join(confirmed + uncertain)
        + "; live solve may continue with inherited child or Sol-only",
    }


def _gpu_image_probe(
    profile: str,
    command: Sequence[str],
    *,
    run: Callable[..., subprocess.CompletedProcess[str]] = _run,
) -> subprocess.CompletedProcess[str]:
    argv = [
        "docker", "run", "--rm", "--pull", "never", "--gpus", "all",
        "--network", "none", "--read-only",
        "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
        "--user", "1001:1001",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
        "--tmpfs", "/work:rw,nosuid,nodev,size=256m,mode=1777",
        "--env", "HOME=/work", "--env", "XDG_DATA_HOME=/work/.local/share",
        "--env", "NVIDIA_DRIVER_CAPABILITIES=compute,utility",
        "--entrypoint", command[0], f"ctf-os-sandbox:{profile}", *command[1:],
    ]
    return run(argv, timeout=60)


def _gpu_doctor_checks(
    gpu: Mapping[str, object],
    image_present: Mapping[str, bool],
    *,
    probe: Callable[[str, Sequence[str]], subprocess.CompletedProcess[str]] = _gpu_image_probe,
) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []

    def add(
        name: str, ok: bool, detail: str, *, skipped: bool = False,
        fix: str | None = None,
    ) -> None:
        item: dict[str, object] = {
            "name": name, "ok": ok,
            "status": "SKIPPED" if skipped else "PASS" if ok else "FAIL",
            "detail": detail,
        }
        if not ok and fix:
            item["fix"] = fix
        checks.append(item)

    host_driver = bool(gpu.get("host_driver"))
    detection_status = str(gpu.get("status") or "UNAVAILABLE")
    if not host_driver:
        if detection_status == "DEGRADED":
            add(
                "gpu-host-driver", False, str(gpu.get("reason") or "nvidia-smi failed"),
                fix="repair the host NVIDIA driver and nvidia-smi",
            )
        else:
            add(
                "gpu-host-driver", True,
                str(gpu.get("reason") or "no NVIDIA GPU detected; CPU fallback active"),
                skipped=True,
            )
        for name in (
            "gpu-docker-passthrough", "gpu-ai-torch", "gpu-ai-onnx",
            "gpu-crypto-hashcat", "gpu-rev-runtime",
        ):
            add(name, True, "no usable host NVIDIA GPU; CPU fallback active", skipped=True)
        return checks

    device_count = int(gpu.get("device_count") or 0)
    add("gpu-host-driver", True, f"nvidia-smi detected {device_count} NVIDIA GPU(s)")
    passthrough = bool(gpu.get("available") and gpu.get("docker_passthrough"))
    add(
        "gpu-docker-passthrough", passthrough,
        str(
            gpu.get("passthrough_detail") or gpu.get("reason")
            or "container nvidia-smi passed"
        ),
        fix="install/configure NVIDIA Container Toolkit for Docker --gpus device requests",
    )
    probes: tuple[tuple[str, str, Sequence[str]], ...] = (
        ("gpu-ai-torch", "ai", ("python3", "-c", GPU_AI_TORCH_PROBE)),
        ("gpu-ai-onnx", "ai", ("python3", "-c", GPU_AI_ONNX_PROBE)),
        (
            "gpu-crypto-hashcat", "crypto",
            ("sh", "-ec", "output=$(hashcat -I 2>&1); printf '%s\\n' \"$output\"; printf '%s\\n' \"$output\" | grep -qiE 'NVIDIA|CUDA'"),
        ),
        ("gpu-rev-runtime", "rev", ("python3", "-c", GPU_REV_PROBE)),
    )
    for name, profile, command in probes:
        if not passthrough:
            add(name, True, "Docker GPU passthrough unavailable; framework probe not run", skipped=True)
            continue
        if not image_present.get(profile, False):
            add(name, True, f"ctf-os-sandbox:{profile} is not present", skipped=True)
            continue
        result = probe(profile, command)
        streams = "\n".join(
            part.strip() for part in (result.stdout, result.stderr) if part.strip()
        )
        add(
            name, result.returncode == 0,
            (streams or "real GPU operation passed")[-8_000:],
            fix=f"rebuild ctf-os-sandbox:{profile} and verify its GPU runtime dependencies",
        )
    return checks


def run_doctor(repo: Path) -> dict[str, object]:
    checks: list[dict[str, object]] = []
    warnings: list[str] = []

    def add(name: str, ok: bool, detail: str, fix: str | None = None) -> None:
        item: dict[str, object] = {
            "name": name, "ok": ok, "status": "PASS" if ok else "FAIL", "detail": detail,
        }
        if not ok and fix:
            item["fix"] = fix
        checks.append(item)

    os_release = _os_release()
    distribution = os_release.get("ID", "").casefold()
    machine = platform.machine().casefold()
    kernel_release = platform.release().casefold()
    wsl = "microsoft" in kernel_release or bool(os.environ.get("WSL_INTEROP"))
    wsl_generation = _wsl_generation(kernel_release, wsl)
    distribution_kind = distribution.upper() if distribution else "UNKNOWN"
    runtime_kind = f"{'WSL2' if wsl else 'NATIVE'}_{distribution_kind}"
    supported_host = _supported_host(
        host_system=platform.system(), distribution=distribution, architecture=machine,
        wsl_generation=wsl_generation,
    )
    add(
        "host-platform", bool(supported_host),
        f"host_system={platform.system()} distribution={distribution or 'unknown'} "
        f"distribution_version={os_release.get('VERSION_ID') or 'unknown'} "
        f"architecture={platform.machine()} runtime_kind={runtime_kind} "
        f"kernel_release={platform.release()}",
        "use WSL2 Ubuntu/Kali x86_64 (official) or native Ubuntu/Kali x86_64 (compatible)",
    )
    if wsl:
        add(
            "wsl-version", wsl_generation != 1,
            "WSL2 verified from the Microsoft WSL2 kernel"
            if wsl_generation == 2 else (
                "WSL1 kernel detected" if wsl_generation == 1
                else "WSL marker present; version could not be distinguished, Docker daemon checks remain authoritative"
            ),
            "upgrade this Linux distribution to WSL2",
        )
        systemd_available = _systemd_available()
        detail = (
            "available" if systemd_available else
            "optional warning: systemd is not active; docker daemon is the authoritative runtime check"
        )
        add("systemd", True, detail)
        if not systemd_available:
            warnings.append(detail)
    for executable in ("python3", "uv", "docker"):
        path = shutil.which(executable)
        add(executable, bool(path), path or "not found", f"install {executable} and place it on PATH")
    docker = _run([
        "docker", "info", "--format",
        "{{.ServerVersion}}|{{.OSType}}|{{.Architecture}}|{{.DockerRootDir}}",
    ])
    docker_detail = docker.stdout.strip() or docker.stderr.strip()
    failure_kind = _docker_failure_kind(docker_detail)
    docker_server_version = None
    docker_server_os = None
    docker_server_architecture = None
    docker_root: Path | None = None
    if docker.returncode == 0:
        fields = docker.stdout.strip().split("|", 3)
        if len(fields) == 4:
            docker_server_version, docker_server_os, docker_server_architecture, root_value = fields
            docker_root = Path(root_value) if root_value else None
    socket = Path("/var/run/docker.sock")
    socket_access = docker.returncode == 0 or (
        socket.exists() and os.access(socket, os.R_OK | os.W_OK)
    )
    add(
        "docker-socket-access", socket_access,
        "daemon access verified" if docker.returncode == 0 else (
            f"{socket}: current user lacks read/write access"
            if socket.exists() and not socket_access else f"{socket}: unavailable"
        ),
        "grant the current user Docker socket access; CTF-OS never invokes sudo",
    )
    add(
        "docker-daemon", docker.returncode == 0,
        docker_detail if docker.returncode == 0 else failure_kind,
        "start Docker Engine or correct the reported daemon/socket error",
    )
    server_platform_ok = (
        docker.returncode == 0 and bool(docker_server_version)
        and _docker_server_supported(docker_server_os, docker_server_architecture)
    )
    add(
        "docker-server-platform", server_platform_ok,
        f"ServerVersion={docker_server_version or 'unknown'} "
        f"OSType={docker_server_os or 'unknown'} Architecture={docker_server_architecture or 'unknown'}",
        "use a Docker Engine server running Linux/amd64",
    )
    compose = _run(["docker", "compose", "version", "--short"])
    compose_version = compose.stdout.strip() or compose.stderr.strip()
    compose_ok = compose.returncode == 0 and _compose_v2(compose.stdout.strip())
    add("docker-compose", compose_ok, compose_version, "install Docker Compose v2")
    build_command = _run(["docker", "build", "--help"])
    run_command = _run(["docker", "run", "--help"])
    add("docker-build-command", build_command.returncode == 0, "available" if build_command.returncode == 0 else build_command.stderr.strip(), "install a Docker CLI with docker build")
    add("docker-run-command", run_command.returncode == 0, "available" if run_command.returncode == 0 else run_command.stderr.strip(), "install a Docker CLI with docker run")

    image_present: dict[str, bool] = {}
    if docker.returncode == 0:
        for profile, image in zip(PROFILES, IMAGES, strict=True):
            present = _run(["docker", "image", "inspect", image])
            image_present[profile] = present.returncode == 0
            add(f"image-{profile}", present.returncode == 0, "tag present" if present.returncode == 0 else present.stderr.strip(), f"run sandbox/build-images.sh {profile}")
            if present.returncode == 0:
                smoke = _image_probe(profile)
                streams = "\n".join(part.strip() for part in (smoke.stdout, smoke.stderr) if part.strip())
                detail = streams or "all required binary/import/operation probes passed"
                add(f"image-{profile}-tools", smoke.returncode == 0, detail[-8_000:], f"rebuild ctf-os-sandbox:{profile}")
        if all(_run(["docker", "image", "inspect", image]).returncode == 0 for image in IMAGES):
            lifecycle_ok, lifecycle_detail = _sandbox_lifecycle_probe()
            add("sandbox-lifecycle", lifecycle_ok, lifecycle_detail, "rebuild ctf-os-sandbox:base and run sandbox-gc")
        else:
            add("sandbox-lifecycle", False, "one or more category images are missing", "run sandbox/build-images.sh")
    else:
        for profile in PROFILES:
            image_present[profile] = False
            add(f"image-{profile}", False, "Docker daemon unavailable", f"run sandbox/build-images.sh {profile}")
        add("sandbox-lifecycle", False, "Docker daemon unavailable", "start Docker and run sandbox/build-images.sh")

    disk = shutil.disk_usage(repo)
    add("disk-space", disk.free >= 20 * 1024**3, f"{disk.free // 1024**3} GiB free", "free at least 20 GiB")
    if docker.returncode == 0:
        try:
            docker_disk = shutil.disk_usage(docker_root) if docker_root else None
        except OSError:
            docker_disk = None
        add(
            "docker-data-root-space", bool(docker_disk and docker_disk.free >= 20 * 1024**3),
            f"{docker_disk.free // 1024**3} GiB free at {docker_root}" if docker_disk else "Docker data-root cannot be inspected",
            "free at least 20 GiB in Docker data-root",
        )
    memory_bytes = _available_memory()
    add("memory", memory_bytes >= 2 * 1024**3, f"{memory_bytes // 1024**3} GiB available", "free at least 2 GiB RAM")
    add("repository-write", _write_probe(repo), str(repo), "make the repository writable")
    add("output-write", _write_probe(repo / "output"), str(repo / "output"), "make repository output/ writable and remove unsafe symlinks")
    filesystem = _repository_filesystem(repo)
    if filesystem["windows_mount"]:
        warning = (
            "Docker build context, forensic extraction, receipt ledger, and many-file atomic operations "
            "perform better on the WSL2 Linux filesystem; prefer /home/<user>/CTF-OS"
        )
        warnings.append(warning)
        add("repository-filesystem", True, f"WARNING: {warning}; mount={filesystem['mount']} fstype={filesystem['fstype']}")
    else:
        add(
            "repository-filesystem", True,
            f"Linux filesystem mount={filesystem['mount']} fstype={filesystem['fstype']}",
        )

    if docker.returncode == 0 and server_platform_ok:
        outbound_ok, outbound_detail = _docker_outbound_probe()
        add("docker-container-outbound-network", outbound_ok, outbound_detail, "restore outbound Docker bridge connectivity")
        bridge_ok, bridge_detail = _docker_bridge_probe()
        add("docker-bridge-network", bridge_ok, bridge_detail, "allow Docker bridge network create/inspect/remove")
        service_ok, service_detail = _compose_network_probe()
        add("compose-service-network", service_ok, service_detail, "repair Docker Compose v2 service networking")
    else:
        for name in (
            "docker-container-outbound-network", "docker-bridge-network", "compose-service-network",
        ):
            add(name, False, "Docker Linux/amd64 daemon unavailable", "restore the Docker Engine runtime first")

    skill_files = [repo / f".codex/skills/{name}/SKILL.md" for name in ("ctf-intake", "ctf-triage", "ctf-solve")]
    playbooks = list((repo / "ctf_os/resources/knowledge/playbooks").glob("*.md"))
    add("skills", all(path.is_file() and not path.is_symlink() for path in skill_files), ", ".join(str(path) for path in skill_files), "restore the tracked skill files")
    add("playbooks", len(playbooks) >= 9, f"{len(playbooks)} files", "restore all nine category playbooks")
    template_path = repo / "ctf_os/resources/delegation-templates.yaml"
    try:
        templates = load_templates(template_path)
        template_ok, template_detail = len(templates) >= 9, f"{len(templates)} categories"
    except (DelegationError, OSError) as exc:
        template_ok, template_detail = False, str(exc)
    add("delegation-templates", template_ok, template_detail, "restore the validated delegation template resource")
    try:
        timeout_profiles = load_timeout_profiles(repo / "ctf_os/resources/timeout-profiles.yaml")
        timeout_ok, timeout_detail = len(timeout_profiles) == 9, f"{len(timeout_profiles)} profiles"
    except (TimeoutProfileError, OSError) as exc:
        timeout_ok, timeout_detail = False, str(exc)
    add("timeout-profiles", timeout_ok, timeout_detail, "restore the validated timeout profile resource")
    add("service-runtime", importlib.util.find_spec("ctf_os.service") is not None, "ctf_os.service", "restore the service runtime module")
    add("replay-runtime", importlib.util.find_spec("ctf_os.replay") is not None, "ctf_os.replay", "restore the replay module")
    benchmark_modules = (
        "ctf_os.attempts", "ctf_os.race_lineage", "ctf_os.benchmark_lock",
        "ctf_os.benchmark_manifest", "ctf_os.benchmark_schedule",
        "ctf_os.benchmark_telemetry",
    )
    add(
        "attempt-lineage-benchmark-runtime",
        all(importlib.util.find_spec(name) is not None for name in benchmark_modules)
        and importlib.util.find_spec("cryptography.hazmat.primitives.asymmetric.ed25519") is not None,
        ", ".join(benchmark_modules) + ", Ed25519",
        "run uv sync --frozen and restore attempt/lineage/benchmark runtime modules",
    )

    # Doctor owns sandbox health, not another active solve's shared service.
    # Count only stopped worker sandboxes that sandbox-gc can safely remove;
    # active race sandboxes and exact-label service lifecycles are not stale.
    stale_sandboxes = _run([
        "docker", "ps", "-aq", "--filter", "label=ctf-os=true",
        "--filter", "label=ctf-os.kind=sandbox", "--filter", "status=exited",
    ]) if docker.returncode == 0 else subprocess.CompletedProcess([], 1, "", "")
    stale_count = len(stale_sandboxes.stdout.split())
    add("stale-resources", stale_count == 0, f"{stale_count} stopped sandbox resources", "run sandbox-gc for stopped sandboxes")
    checks.extend(_gpu_doctor_checks(detect_gpus(), image_present))
    model_routing = inspect_codex_routing_capabilities(repo)
    routing_warnings = [str(item) for item in model_routing.get("warnings", [])]
    warnings.extend(routing_warnings)
    checks.append(_codex_model_routing_check(model_routing))
    return {
        "ok": all(bool(item["ok"]) for item in checks),
        "host_system": platform.system(),
        "linux_distribution": distribution or None,
        "linux_version": os_release.get("VERSION_ID"),
        "architecture": platform.machine(),
        "runtime_kind": runtime_kind,
        "kernel_release": platform.release(),
        "docker_server_version": docker_server_version,
        "docker_server_os": docker_server_os,
        "docker_server_architecture": docker_server_architecture,
        "compose_version": compose.stdout.strip() if compose.returncode == 0 else None,
        "warnings": warnings,
        "model_routing": model_routing,
        "checks": checks,
    }


def _os_release() -> dict[str, str]:
    try:
        values: dict[str, str] = {}
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
        return values
    except OSError:
        return {}


def _wsl_generation(kernel_release: str, detected: bool) -> int | None:
    if not detected:
        return None
    lowered = kernel_release.casefold()
    if "wsl2" in lowered or "microsoft-standard" in lowered:
        return 2
    if lowered.startswith("4.4.") and "microsoft" in lowered:
        return 1
    return None


def _supported_host(
    *, host_system: str, distribution: str, architecture: str,
    wsl_generation: int | None,
) -> bool:
    return (
        host_system == "Linux" and distribution.casefold() in {"ubuntu", "kali"}
        and architecture.casefold() in {"x86_64", "amd64"}
        and wsl_generation != 1
    )


def _docker_server_supported(os_type: str | None, architecture: str | None) -> bool:
    return (
        str(os_type).casefold() == "linux"
        and str(architecture).casefold() in {"x86_64", "amd64"}
    )


def _systemd_available() -> bool:
    try:
        return Path("/run/systemd/system").is_dir() or Path("/proc/1/comm").read_text(
            encoding="ascii",
        ).strip() == "systemd"
    except OSError:
        return False


def _compose_v2(value: str) -> bool:
    normalized = value.strip().removeprefix("v")
    return normalized.split(".", 1)[0] == "2"


def _repository_filesystem(repo: Path) -> dict[str, object]:
    resolved = repo.resolve()
    mount = "/"
    fstype = "unknown"
    try:
        rows = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError:
        rows = []
    best = -1
    for row in rows:
        fields = row.split()
        if "-" not in fields or len(fields) < 7:
            continue
        separator = fields.index("-")
        candidate = fields[4].replace("\\040", " ")
        try:
            resolved.relative_to(candidate)
        except ValueError:
            continue
        if len(candidate) > best and separator + 1 < len(fields):
            best = len(candidate)
            mount = candidate
            fstype = fields[separator + 1]
    windows_path = len(resolved.parts) >= 3 and resolved.parts[1] == "mnt" and len(resolved.parts[2]) == 1
    return {
        "mount": mount, "fstype": fstype,
        "windows_mount": windows_path or fstype.casefold() == "drvfs",
    }


def _docker_failure_kind(detail: str) -> str:
    lowered = detail.casefold()
    if "permission denied" in lowered:
        return f"SOCKET_PERMISSION_DENIED: {detail}"
    if "cannot connect" in lowered or "connection refused" in lowered:
        return f"DAEMON_STOPPED_OR_UNREACHABLE: {detail}"
    if not shutil.which("docker"):
        return "DOCKER_CLI_MISSING"
    return f"DAEMON_RESPONSE_ERROR: {detail or 'no daemon response'}"


def _docker_outbound_probe() -> tuple[bool, str]:
    result = _run([
        "docker", "run", "--rm", "--network", "bridge",
        "--entrypoint", "python3", "ctf-os-sandbox:base", "-c",
        "import socket; s=socket.create_connection(('1.1.1.1',443),10); s.close()",
    ], timeout=30)
    detail = result.stdout.strip() or result.stderr.strip()
    return result.returncode == 0, detail or "container reached an external TCP endpoint"


def _docker_bridge_probe() -> tuple[bool, str]:
    name = f"ctf-os-doctor-bridge-{os.getpid()}"
    created = _run(["docker", "network", "create", "--driver", "bridge", name])
    try:
        inspected = _run([
            "docker", "network", "inspect", "--format", "{{.Driver}}|{{.Internal}}", name,
        ]) if created.returncode == 0 else created
        ok = created.returncode == 0 and inspected.returncode == 0 and inspected.stdout.strip() == "bridge|false"
        detail = inspected.stdout.strip() or inspected.stderr.strip() or created.stderr.strip()
        return ok, detail or "bridge network create/inspect passed"
    finally:
        if created.returncode == 0:
            _run(["docker", "network", "rm", name])


def _compose_network_probe() -> tuple[bool, str]:
    project = f"ctfosdoctor{os.getpid()}"
    with tempfile.TemporaryDirectory(prefix="ctf-os-compose-doctor-") as temporary:
        root = Path(temporary)
        compose_file = root / "compose.yaml"
        compose_file.write_text(
            "services:\n"
            "  probe:\n"
            "    image: ctf-os-sandbox:base\n"
            "    command: [\"sleep\", \"30\"]\n",
            encoding="utf-8",
        )
        argv = [
            "docker", "compose", "--project-name", project,
            "--file", str(compose_file),
        ]
        started = _run([*argv, "up", "--detach", "--no-build"], timeout=60, cwd=root)
        try:
            network = _run([
                "docker", "network", "inspect", "--format", "{{.Driver}}", f"{project}_default",
            ]) if started.returncode == 0 else started
            ok = started.returncode == 0 and network.returncode == 0 and network.stdout.strip() == "bridge"
            detail = network.stdout.strip() or network.stderr.strip() or started.stderr.strip()
            return ok, detail or "Compose service network create/inspect passed"
        finally:
            _run([*argv, "down", "--volumes", "--remove-orphans"], timeout=60, cwd=root)


def _available_memory() -> int:
    try:
        line = next(line for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines() if line.startswith("MemAvailable:"))
        return int(line.split()[1]) * 1024
    except (OSError, StopIteration, ValueError):
        return 0


def _write_probe(output: Path) -> bool:
    if output.is_symlink():
        return False
    try:
        output.mkdir(parents=True, exist_ok=True)
        probe = output / ".doctor-write-probe"
        probe.write_text("ok", encoding="ascii")
        probe.unlink()
        return True
    except OSError:
        return False


def _sandbox_lifecycle_probe() -> tuple[bool, str]:
    metadata: dict[str, object] | None = None
    with tempfile.TemporaryDirectory(prefix="ctf-os-doctor-") as temporary:
        root = Path(temporary) / "challenge"
        source = root / "input"
        source.mkdir(parents=True)
        (source / "probe").write_text("ok", encoding="ascii")
        try:
            metadata = create(SandboxSpec("doctor", "probe", "smoke", source, root / "workers" / "smoke", image="ctf-os-sandbox:base", resource_profile="light"))
            receipt = execute(metadata, ["sh", "-c", "test -r /challenge/probe && ! test -w /challenge/probe && test -w /work && test -w /artifacts && test $(id -u) = 1001"], 20)
            cleaned = cleanup(metadata)
            ok = receipt["exit_code"] == 0 and cleaned["removed"] is True
            return ok, "non-root create/ro-challenge/rw-work/rw-artifacts/exec/export/cleanup passed" if ok else f"receipt={receipt}, cleanup={cleaned}"
        except Exception as exc:
            cleanup_error = ""
            if metadata is not None:
                try:
                    cleanup(metadata)
                except Exception as cleanup_exc:
                    cleanup_error = f"; cleanup also failed: {cleanup_exc}"
            return False, f"{exc}{cleanup_error}"
