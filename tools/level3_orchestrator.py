#!/usr/bin/env python3
"""Coordinate Level 3 CTF worker planning, merge, and evaluation."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STATE_NAME = "LEVEL3_STATE.json"
TASKS_NAME = "LEVEL3_TASKS.json"
DISPATCH_NAME = "LEVEL3_DISPATCH.json"
DISPATCH_MARKDOWN = "LEVEL3_DISPATCH.md"
DISPATCH_DIR = "level3_dispatch"
RUN_LOG = "LEVEL3_RUN_LOG.jsonl"
ATTEMPT_MATRIX = "ATTEMPT_MATRIX.md"
MUTATION_LEDGER = "MUTATION_LEDGER.md"
ALLOWED_WORKER_STATUSES = {"PASS", "FAIL", "INCONCLUSIVE"}
RESULT_CLASSES = {"CONFIRMED", "NEGATIVE", "SIDE_EFFECT", "INCONCLUSIVE"}
ACTIVE_TASK_STATUSES = {"pending", "dispatched"}

CATEGORY_ALIASES = {
    "reverse": "rev",
    "re": "rev",
    "forensic": "forensics",
    "ppc": "programming",
    "prog": "programming",
    "sandbox": "jail",
    "blockchain": "web3",
    "smart-contract": "web3",
    "k8s": "container",
    "kubernetes": "container",
    "ai": "ai-ml",
    "ml": "ai-ml",
    "hardware": "hardware-rf",
    "rf": "hardware-rf",
    "sidechannel": "side-channel",
}

CATEGORY_WORKERS: dict[str, list[tuple[str, str]]] = {
    "web": [
        ("auth_session", "Prove or disprove authentication, role, cookie, and feature-transition paths."),
        ("source_disclosure", "Find source/file disclosure or document why parser and encoding paths fail."),
        ("policy_oracle", "Explore ACL, grant, policy, SQL, expression, or report oracles under budget."),
        ("state_mutation", "Map state-changing routes and record side effects before exploit chaining."),
        ("render_runtime", "Test preview, upload, archive, scheduler, and template/render behavior."),
        ("ssrf_internal", "Determine whether internal reachability can become a useful side effect or disclosure."),
    ],
    "pwn": [
        ("env_repro", "Reproduce the local binary, libc, loader, Docker, and service environment."),
        ("crash_triage", "Classify crash primitives, input control, mitigations, and stability."),
        ("primitive", "Turn crashes into leaks, writes, control-flow, sandbox, or heap primitives."),
        ("exploit_chain", "Assemble a replayable exploit chain and preserve local proof artifacts."),
        ("deadline_remote", "Model remote timing, retries, transcript capture, and exploit decay risk."),
    ],
    "rev": [
        ("static_extract", "Extract constants, algorithms, checks, formats, and control-flow constraints."),
        ("dynamic_trace", "Trace runtime behavior, inputs, outputs, side effects, and anti-analysis paths."),
        ("symbolic", "Use symbolic or constraint solving only when concrete evidence justifies it."),
        ("patch_verify", "Build and verify local patches, emulators, or solver-equivalent proofs."),
        ("deadline_remote", "Model remote round timing, protocol capture, and timeout-aware strategies."),
    ],
    "crypto": [
        ("parameter_extract", "Recover public parameters, ciphertexts, oracle behavior, and protocol transcript."),
        ("math_attack", "Identify and test concrete attacks against the observed primitive."),
        ("oracle_model", "Model adaptive oracle, padding, timing, or signing behavior with reproducible queries."),
        ("solver_verify", "Produce a deterministic solver and validate recovered plaintext or key material."),
    ],
    "forensics": [
        ("artifact_inventory", "Hash, classify, and index files, images, packets, archives, and memory artifacts."),
        ("timeline", "Build event timelines from metadata, logs, filesystems, or packet chronology."),
        ("carving", "Recover embedded files, streams, archives, deleted records, or hidden payloads."),
        ("memory_network", "Analyze memory, process, socket, DNS, HTTP, or protocol evidence."),
        ("crypto_bridge", "Route carved encrypted material or keys into crypto analysis when evidence demands it."),
    ],
    "misc": [
        ("protocol_model", "Model custom protocol states, tokens, grammar, and transition behavior."),
        ("parser_state", "Explore parsing ambiguity, serialization, compression, encoding, and format quirks."),
        ("automation_solver", "Build deterministic automation for interactive, PPC, or search-heavy tasks."),
        ("category_router", "Escalate to a narrower category only when a concrete artifact changes domain."),
    ],
    "programming": [
        ("problem_model", "Extract constraints, samples, input/output grammar, and complexity bounds."),
        ("solver_build", "Build a deterministic solver with local tests and saved output."),
        ("remote_runner", "Automate remote interaction with timeouts, retries, and transcript capture."),
        ("verifier", "Verify solver output against samples, local checker, or replay transcript."),
    ],
    "jail": [
        ("constraint_model", "Model interpreter version, blacklist, allowlist, parser, and execution limits."),
        ("payload_search", "Explore bypass families without repeating equivalent payload spellings."),
        ("environment_delta", "Compare local and remote jail behavior before relying on a payload."),
        ("bypass_verify", "Capture accepted payload, output, and replayable proof command."),
    ],
    "stego": [
        ("carrier_inventory", "Hash, classify, and preserve carrier metadata before extraction."),
        ("metadata_streams", "Analyze metadata, chunks, frames, channels, and embedded streams."),
        ("signal_bits", "Test bit-plane, palette, audio, timing, and transform hypotheses."),
        ("extraction_chain", "Preserve recovered artifacts with source offsets, commands, and hashes."),
    ],
    "osint": [
        ("source_inventory", "List candidate public sources with access dates and scope checks."),
        ("identity_disambiguation", "Resolve handles, names, domains, or images without over-attribution."),
        ("archive_geo_time", "Check archives, geolocation, timeline, and historical context."),
        ("citation_proof", "Preserve URLs, screenshots, and reasoning needed for answer proof."),
    ],
    "mobile": [
        ("package_inventory", "Hash APK/IPA artifacts, manifests, resources, signing, and native libraries."),
        ("static_decompile", "Recover Java/Kotlin/Swift/native logic and high-value constants."),
        ("secret_logic", "Extract keys, endpoints, crypto, storage, and feature-gate behavior."),
        ("protocol_replay", "Replay app API or local verifier behavior without needing device-only state."),
    ],
    "malware": [
        ("static_triage", "Hash and statically classify suspicious artifacts before execution."),
        ("unpack_config", "Recover packed layers, config, strings, C2-like clues, and decryptors safely."),
        ("behavior_model", "Model persistence, files, network, process, and memory behavior from evidence."),
        ("safe_verifier", "Validate extracted payload or config without unsafe uncontrolled execution."),
    ],
    "web3": [
        ("contract_inventory", "Collect contracts, ABI, bytecode, addresses, balances, and transaction logs."),
        ("state_model", "Model storage, access control, block assumptions, and invariant targets."),
        ("exploit_transaction", "Build local fork or script proof for the exploit transaction path."),
        ("replay_verify", "Verify final state transition, recovered value, or flag claim deterministically."),
    ],
    "cloud": [
        ("scope_inventory", "Freeze authorization boundary, configs, credentials handling, and lab endpoints."),
        ("identity_policy", "Analyze IAM-like policy, metadata, role assumption, and service permissions."),
        ("service_path", "Map storage, serverless, metadata, logs, and deployment paths."),
        ("proof_path", "Preserve local or owned-scope command transcript and proof output."),
    ],
    "container": [
        ("image_inventory", "Hash images, Dockerfiles, manifests, layers, users, caps, mounts, and secrets."),
        ("namespace_runtime", "Reproduce runtime, namespace, cgroup, socket, and filesystem behavior locally."),
        ("escape_surface", "Analyze privilege, mounts, kernel interfaces, Kubernetes context, and breakout paths."),
        ("proof_path", "Capture replayable container or cluster-local proof within challenge scope."),
    ],
    "ai-ml": [
        ("prompt_context", "Freeze prompts, hidden instructions, tool descriptions, datasets, and transcripts."),
        ("model_behavior", "Sample behavior, classifiers, embeddings, and non-determinism under controlled inputs."),
        ("tool_chain", "Analyze agent tools, retrieval, browser actions, and downstream web/API effects."),
        ("replay_prompt", "Produce reproducible prompts, seeds when available, outputs, and proof transcript."),
    ],
    "hardware-rf": [
        ("capture_inventory", "Record capture metadata, sample rate, format, channel, firmware, and hashes."),
        ("signal_decode", "Analyze modulation, framing, symbols, clocking, and decoded packets."),
        ("protocol_recover", "Recover protocol fields, payloads, keys, or firmware bridge artifacts."),
        ("replay_verify", "Verify recovered data through scripts and preserved trace provenance."),
    ],
    "side-channel": [
        ("trace_inventory", "Record raw traces, timing logs, sample counts, metadata, and oracle behavior."),
        ("leakage_model", "Model timing, power, cache, fault, or statistical leakage hypotheses."),
        ("statistical_attack", "Run bounded analysis with sample-size and confidence notes."),
        ("verifier", "Verify recovered secret with an independent deterministic check."),
    ],
    "hybrid": [
        ("boundary_artifact", "Identify the concrete artifact that moves the solve between categories."),
        ("handoff_chain", "Order category handoffs with evidence and stop conditions."),
        ("integrated_replay", "Build one replay path across intermediate artifacts."),
        ("proof_scope", "Validate final proof scope and prevent category assumptions from replacing evidence."),
    ],
}

COMMON_WORKERS = [
    ("hypothesis", "Build the hypothesis tree, deduplicate known negatives, and assign bounded branches."),
    ("evidence", "Maintain replay, proof, redaction, liveness, attempt matrix, and mutation ledger hygiene."),
]

COMMON_STRATEGIES: dict[str, dict[str, list[str]]] = {
    "hypothesis": {
        "playbook": [
            "Freeze prompt, assets, service URLs, existing notes, and replay/proof metadata before branching.",
            "Build a hypothesis tree that separates vulnerability class, required primitive, and proof path.",
            "Collapse duplicate negatives by input shape and target instead of retrying equivalent probes.",
            "Repartition the search space when every branch in one family is negative.",
        ],
        "tools": ["notes.md", "state.json", f"work/{ATTEMPT_MATRIX}", f"work/{STATE_NAME}"],
        "evidence_required": ["hypothesis tree", "known-negative families", "next worker assignments"],
        "failure_modes": ["unbounded brainstorming", "payload repetition", "missing stop condition"],
    },
    "evidence": {
        "playbook": [
            "Check proof_scope, replay_kind, remote_status, remote_solve, and current_remote_liveness before claiming progress.",
            "Keep sensitive raw logs under evidence/ and summarize redacted facts in notes.md.",
            "Reject worker facts that lack existing artifacts, commands, transcripts, hashes, or saved responses.",
            "Never rerun remote_live or remote_live_exploit replay without explicit operator opt-in.",
        ],
        "tools": ["tools/proof_validate.py", "tools/replay_runner.py", "state.json", "evidence/"],
        "evidence_required": ["proof_validate result", "artifact paths", "redaction/liveness decision"],
        "failure_modes": ["stale liveness", "merged claim without artifact", "flag leakage in public summary"],
    },
}

CATEGORY_DEFAULT_STRATEGIES: dict[str, dict[str, list[str]]] = {
    "web": {
        "playbook": [
            "Inventory routes, roles, content types, parser boundaries, and state-changing methods before mutation.",
            "Branch auth, source disclosure, oracle, state mutation, render/upload, and SSRF separately.",
            "Record both positive responses and negative payload families with exact request shape.",
        ],
        "tools": ["curl/httpie", "python requests", "browser/playwright when UI state matters", "saved HTTP transcripts"],
        "evidence_required": ["request/response transcript", "route or endpoint target", "mutation ledger row when state changes"],
        "failure_modes": ["cookie drift", "CSRF/session mismatch", "mutating state without ledger", "source leak and runtime exploit conflation"],
    },
    "pwn": {
        "playbook": [
            "Reproduce binary, libc, loader, container, argv/env, seccomp, and network wrapper before exploit work.",
            "Classify mitigations and crash control, then prove one primitive at a time.",
            "Keep local exploit proof separate from remote liveness and deadline behavior.",
        ],
        "tools": ["checksec", "gdb", "pwntools", "ROPgadget", "one_gadget", "seccomp-tools", "Docker"],
        "evidence_required": ["binary/libc hashes", "mitigation output", "crash or exploit transcript", "local replay command"],
        "failure_modes": ["libc mismatch", "ASLR leak assumption", "remote timeout not modeled", "one-shot exploit without transcript"],
    },
    "rev": {
        "playbook": [
            "Extract constants, formats, and check functions statically before symbolic expansion.",
            "Use concrete traces to bound symbolic state and patch loops.",
            "Produce a verifier or solver-equivalent proof rather than relying on decompiler guesses.",
        ],
        "tools": [".codex/bin/r2", ".codex/bin/angr-mcp", "gdb/ltrace/strace", "python solver"],
        "evidence_required": ["offset/function reference", "trace or decompile excerpt", "solver/verifier artifact"],
        "failure_modes": ["symbolic state explosion", "patched binary proves different semantics", "anti-analysis false negative"],
    },
    "crypto": {
        "playbook": [
            "Extract exact parameters, encodings, transcript order, and oracle semantics before choosing math.",
            "Model oracle adaptivity, rate limits, and noise separately from the attack script.",
            "Verify recovered plaintext/key material with an independent deterministic check.",
        ],
        "tools": ["sage", "python", "z3 when installed", "transcript logs"],
        "evidence_required": ["parameter dump", "attack assumption", "oracle transcript or local verifier"],
        "failure_modes": ["wrong modulus/order", "encoding mismatch", "oracle noise mistaken for signal", "unverified recovered secret"],
    },
    "forensics": {
        "playbook": [
            "Hash and classify every artifact before carving or mutation.",
            "Build timeline, container/archive chain, memory/network chain, and crypto bridge independently.",
            "Preserve extracted files with source offsets, commands, and hashes.",
        ],
        "tools": ["file", "sha256sum", "binwalk", "foremost/photorec when installed", "tshark", "strings"],
        "evidence_required": ["artifact inventory", "command log", "hashes", "extraction provenance"],
        "failure_modes": ["destructive extraction", "lost offset provenance", "timeline without timezone", "decoded artifact not rehashed"],
    },
    "misc": {
        "playbook": [
            "Model protocol, parser, automation, and category-router branches independently.",
            "Prefer deterministic solvers over interactive manual progress once the state machine is known.",
            "Escalate to a narrower category only after an artifact proves the domain change.",
        ],
        "tools": ["python", "netcat/socat", "custom parser", "notes.md"],
        "evidence_required": ["state model", "input/output samples", "automation artifact"],
        "failure_modes": ["over-routing before evidence", "manual-only PPC progress", "parser ambiguity not recorded"],
    },
    "programming": {
        "playbook": [
            "Extract constraints, samples, input/output grammar, and complexity before coding.",
            "Build deterministic local tests before remote automation.",
            "Capture final remote transcript and make replay.sh reproduce the solver path.",
        ],
        "tools": ["python", "sample tests", "socket/pwntools when interactive", "timeout"],
        "evidence_required": ["constraints", "solver script", "sample pass output", "final transcript"],
        "failure_modes": ["manual-only solve", "hidden remote state", "unbounded search", "missing sample verification"],
    },
    "jail": {
        "playbook": [
            "Model interpreter, version, blacklist, allowlist, parser, and evaluation context first.",
            "Group payloads by bypass family rather than spelling variants.",
            "Compare local and remote behavior before claiming a bypass.",
        ],
        "tools": ["python/node/shell as applicable", "payload log", "source review", "saved errors"],
        "evidence_required": ["constraint model", "payload attempts", "accepted bypass transcript"],
        "failure_modes": ["unknown interpreter version", "payload not replayable", "local/remote mismatch"],
    },
    "stego": {
        "playbook": [
            "Hash and classify carrier files before extraction.",
            "Test metadata, streams, chunks, frames, palettes, channels, and bit hypotheses with provenance.",
            "Rehash and route recovered artifacts instead of continuing blind extraction.",
        ],
        "tools": ["file", "sha256sum", "exiftool/binwalk/zsteg when installed", "python"],
        "evidence_required": ["carrier hash", "metadata or extraction log", "recovered artifact provenance"],
        "failure_modes": ["blind bulk extraction", "lossy carrier assumption", "missing source offsets"],
    },
    "osint": {
        "playbook": [
            "Confirm challenge scope and avoid private or unrelated real-world targeting.",
            "Track sources, access dates, archives, screenshots, and disambiguation criteria.",
            "Preserve a citation-backed reasoning chain for the final answer.",
        ],
        "tools": ["browser/search", "archives", "screenshots", "notes.md"],
        "evidence_required": ["source URL", "access date", "screenshot or archive", "reasoning chain"],
        "failure_modes": ["ambiguous identity", "uncited claim", "scope/privacy issue"],
    },
    "mobile": {
        "playbook": [
            "Inventory APK/IPA manifests, resources, signing, native libraries, and app data.",
            "Decompile only when artifact evidence justifies it and preserve extracted snippets.",
            "Replay recovered API, crypto, or local verifier behavior outside device-only state when possible.",
        ],
        "tools": ["jadx", "apktool", "strings", "python", "traffic transcripts"],
        "evidence_required": ["package hash", "manifest/resource extract", "decompiled finding", "replay proof"],
        "failure_modes": ["device-only assumption", "tooling without artifact", "unverified recovered secret"],
    },
    "malware": {
        "playbook": [
            "Start static-first and do not execute suspicious samples without a safe local plan.",
            "Recover packed layers, config, strings, decryptors, and behavior from evidence.",
            "Validate extracted config or payload with narrow scripts rather than uncontrolled execution.",
        ],
        "tools": ["file", "sha256sum", "strings", "r2/angr when needed", "memory/pcap tools"],
        "evidence_required": ["sample hash", "static finding", "config or decryptor artifact", "safe verifier"],
        "failure_modes": ["unsafe execution", "packed sample without unpacking evidence", "missing sandbox context"],
    },
    "web3": {
        "playbook": [
            "Collect contracts, ABI, bytecode, addresses, balances, transaction logs, and local fork state.",
            "Model storage, access control, block assumptions, and target invariant before exploit scripting.",
            "Verify exploit transactions locally and preserve final state proof.",
        ],
        "tools": ["forge/cast when available", "python/web3", "transaction logs", "local fork"],
        "evidence_required": ["contract/state inventory", "exploit transaction", "state transition proof"],
        "failure_modes": ["external account scope issue", "non-deterministic block assumption", "unverified tx result"],
    },
    "cloud": {
        "playbook": [
            "Freeze scope, challenge-provided credentials, configs, and owned lab endpoints before commands.",
            "Analyze identity policy, metadata, storage, serverless, logs, and deployment paths independently.",
            "Do not store secrets in public notes; preserve sanitized command transcripts.",
        ],
        "tools": ["local config parsers", "provider CLI only in owned scope", "jq/yq", "logs"],
        "evidence_required": ["scope statement", "config/policy finding", "sanitized command transcript"],
        "failure_modes": ["unclear authorization", "secret leakage", "real third-party target"],
    },
    "container": {
        "playbook": [
            "Inventory images, layers, users, caps, mounts, sockets, manifests, and runtime context.",
            "Reproduce behavior locally before considering namespace, Kubernetes, or host interfaces.",
            "Preserve proof commands inside owned challenge scope.",
        ],
        "tools": ["docker", "tar", "jq/yq", "find", "capsh when installed"],
        "evidence_required": ["image digest", "layer/config evidence", "runtime transcript", "proof command"],
        "failure_modes": ["host-specific assumption", "scope boundary unclear", "untracked extracted filesystem"],
    },
    "ai-ml": {
        "playbook": [
            "Freeze prompts, hidden instructions, tool descriptions, datasets, and transcripts.",
            "Sample non-deterministic behavior with controlled inputs and preserve outputs.",
            "Route downstream tool, web, or API effects to the matching category when evidenced.",
        ],
        "tools": ["prompt transcript", "python", "browser/playwright when UI state matters", "sanitized logs"],
        "evidence_required": ["prompt/input", "model output samples", "tool trace or replay prompt"],
        "failure_modes": ["secret required", "non-determinism without samples", "unscoped external system"],
    },
    "hardware-rf": {
        "playbook": [
            "Record sample rate, modulation hints, capture format, channel, firmware, and hashes.",
            "Decode signal and protocol layers with commands and provenance.",
            "Route firmware or recovered crypto material to the appropriate category only after extraction.",
        ],
        "tools": ["file", "sha256sum", "python/numpy", "sigmf metadata", "URH/gnuradio when available"],
        "evidence_required": ["capture metadata", "decode command", "recovered data with provenance"],
        "failure_modes": ["missing sample rate", "hardware-only dependency", "untracked transform"],
    },
    "side-channel": {
        "playbook": [
            "Inventory traces, timing logs, oracle behavior, sample counts, and metadata.",
            "Define leakage model and statistical confidence before recovering secrets.",
            "Verify recovered material through an independent deterministic check.",
        ],
        "tools": ["python/numpy", "sage when math requires it", "plots when useful", "oracle transcripts"],
        "evidence_required": ["trace metadata", "analysis script", "confidence/sample notes", "verifier output"],
        "failure_modes": ["too few samples", "unstable oracle", "unverified recovered secret"],
    },
    "hybrid": {
        "playbook": [
            "Name the concrete boundary artifact that justifies every category switch.",
            "Run each category step with its own evidence and stop condition.",
            "Produce one integrated replay path and validate final proof scope.",
        ],
        "tools": ["category skills", "intermediate artifacts", "replay_runner", "proof_validate"],
        "evidence_required": ["boundary artifact", "handoff notes", "integrated replay", "proof validation"],
        "failure_modes": ["category switch by assumption", "missing intermediate artifact", "proof scope drift"],
    },
}

WORKER_STRATEGY_OVERRIDES: dict[str, dict[str, dict[str, list[str]]]] = {
    "web": {
        "auth_session": {
            "playbook": [
                "Map login, logout, registration, reset, invite, OAuth, role switch, and feature gate transitions.",
                "Diff cookies, JWT/session fields, CSRF tokens, and cacheable identity surfaces across roles.",
                "Record one negative row per auth bypass family, not per payload spelling.",
            ],
            "tools": ["curl/httpie", "python requests.Session", "jwt tooling if present", "browser/playwright for UI-only flows"],
            "evidence_required": ["role-tagged transcript", "cookie/session diff", "negative auth family"],
            "failure_modes": ["testing with stale CSRF", "role confusion caused by cached page", "missing logout boundary"],
        },
        "source_disclosure": {
            "playbook": [
                "Probe path traversal, archive extraction, backup naming, template includes, XXE, and file URL handlers separately.",
                "Treat parser errors and partial source leaks as oracle evidence.",
                "Do not jump from source leak to exploit chain until the leaked primitive is named.",
            ],
            "tools": ["curl", "python payload encoder", "xxe/local file probes", "saved responses"],
            "evidence_required": ["request/response", "parser or path target", "leaked path/source hash when present"],
            "failure_modes": ["encoding variants counted as new hypotheses", "source leak without exploit relevance"],
        },
        "policy_oracle": {
            "playbook": [
                "Map policy inputs: role, owner id, organization id, report id, visibility, and query parameters.",
                "Test boolean, timing, row-count, error-shape, and rendering differences as separate oracle channels.",
                "Keep granted, denied, and indeterminate responses in a compact decision table.",
            ],
            "tools": ["python requests", "diff saved responses", "timing loop only after stable baseline"],
            "evidence_required": ["oracle matrix", "baseline response", "decision difference"],
            "failure_modes": ["network jitter as oracle", "state mutation hidden inside oracle probe"],
        },
        "state_mutation": {
            "playbook": [
                "Inventory POST/PUT/PATCH/DELETE, import, admin, batch, webhook, and background job routes.",
                "For every mutation, record target, action, before, after, and rollback/cleanup status.",
                "Stop immediately if mutation scope becomes unclear and hand off to evidence worker.",
            ],
            "tools": ["curl/httpie", "python requests", f"work/{MUTATION_LEDGER}", "saved JSON"],
            "evidence_required": ["mutation ledger row", "before/after artifact", "request id or response id"],
            "failure_modes": ["remote state drift", "unlogged destructive action", "confusing queued side effect with response"],
        },
        "render_runtime": {
            "playbook": [
                "Separate upload, archive unpack, template render, PDF/image conversion, scheduler, and preview paths.",
                "Capture renderer versions, error traces, output files, and asynchronous timing.",
                "Only chain SSRF/LFI/RCE when a concrete renderer behavior supports it.",
            ],
            "tools": ["browser/playwright", "curl multipart", "local renderer reproduction when possible"],
            "evidence_required": ["uploaded artifact", "rendered output/error", "timing or job id"],
            "failure_modes": ["preview cache mistaken for execution", "async job result not captured"],
        },
        "ssrf_internal": {
            "playbook": [
                "Find URL fetchers, metadata fetchers, webhook callbacks, importers, image proxies, and PDF renderers.",
                "Classify blind, semi-blind, reflected, and stored SSRF channels independently.",
                "Probe internal reachability with low-impact paths and record network side effects.",
            ],
            "tools": ["interactsh-like callback if available", "local listener", "curl", "saved fetch logs"],
            "evidence_required": ["fetch trigger", "callback or response artifact", "target classification"],
            "failure_modes": ["external callback blocked by network but local SSRF still possible", "unsafe internal mutation"],
        },
    },
    "pwn": {
        "deadline_remote": {
            "playbook": [
                "Estimate per-attempt latency, retry count, crash recovery behavior, and proof expiry before remote exploitation.",
                "Use local exploit proof first; remote_live replay requires explicit --allow-remote-live outside this orchestrator.",
                "Capture remote transcript, timing, seed/leak values, and failure reason for every approved live attempt.",
            ],
            "tools": ["pwntools tube logging", "timeout", "script/tee", "tools/replay_runner.py --allow-remote-live only with approval"],
            "evidence_required": ["timing table", "local-vs-remote delta", "approved remote transcript if any"],
            "failure_modes": ["burning attempts without new primitive", "remote exploit rerun without opt-in", "deadline not modeled"],
        },
        "crash_triage": {
            "playbook": [
                "Minimize crashing input and record register, signal, offset, and controlled bytes.",
                "Correlate crash with mitigations, allocator state, and input grammar.",
                "Promote to primitive only when control, leak, or write direction is evidenced.",
            ],
            "tools": ["gdb", "pwndbg/gef if installed", "cyclic/cyclic_find", "core files"],
            "evidence_required": ["crash transcript", "offset/control evidence", "mitigation context"],
            "failure_modes": ["non-deterministic crash treated as primitive", "offset found under wrong input mode"],
        },
    },
    "rev": {
        "symbolic": {
            "playbook": [
                "Start from extracted concrete check boundaries, not whole-program symbolic execution.",
                "Constrain inputs with observed format, length, checksum, and anti-debug conditions.",
                "Save solver script, constraints, and model; verify candidate through the original binary or emulator.",
            ],
            "tools": [".codex/bin/angr-mcp", "z3 when installed", "python", ".codex/bin/r2"],
            "evidence_required": ["constraint script", "model output", "original-binary verification"],
            "failure_modes": ["state explosion", "incorrect unconstrained memory", "candidate not verified concretely"],
        },
        "patch_verify": {
            "playbook": [
                "Patch only to observe or bypass one named check; document original bytes and replacement bytes.",
                "Use patch output to learn constraints, then verify final answer on unpatched semantics.",
                "Keep emulator, deobfuscator, and patch artifacts separate.",
            ],
            "tools": [".codex/bin/r2", "python patcher", "diff/hexdump", "local verifier"],
            "evidence_required": ["patch diff", "reason for patch", "unpatched verification"],
            "failure_modes": ["patch proves a false flag", "lost original bytes", "deobfuscation changes semantics"],
        },
    },
    "crypto": {
        "oracle_model": {
            "playbook": [
                "Define oracle inputs, outputs, error classes, timing budget, adaptivity, and query limits.",
                "Build a local model or transcript replay before adaptive exploitation.",
                "Record negative oracle families such as no timing signal, no padding distinction, or rate-limit noise.",
            ],
            "tools": ["python requests/socket", "statistical timing script", "transcript JSONL"],
            "evidence_required": ["oracle contract", "query transcript", "noise/rate-limit notes"],
            "failure_modes": ["overfitting to transient timing", "query budget exhausted", "ambiguous error class"],
        },
    },
    "forensics": {
        "memory_network": {
            "playbook": [
                "Separate memory process evidence from network packet evidence, then join by timestamp, PID, socket, or key material.",
                "Extract conversations and credentials with hashes and offsets.",
                "Hand encrypted payloads plus recovered keys to crypto_bridge instead of solving inline.",
            ],
            "tools": ["tshark", "strings", "volatility if installed", "grep/rg", "sha256sum"],
            "evidence_required": ["flow/process table", "extracted stream artifact", "join key"],
            "failure_modes": ["timezone mismatch", "flow reassembly without provenance", "credential false positive"],
        },
    },
}

SKILL_FOR_CATEGORY = {
    "web": "skills/ctf-web/SKILL.md",
    "pwn": "skills/ctf-pwn/SKILL.md",
    "rev": "skills/ctf-rev/SKILL.md",
    "crypto": "skills/ctf-crypto/SKILL.md",
    "forensics": "skills/ctf-forensics/SKILL.md",
    "misc": "skills/ctf-misc/SKILL.md",
    "programming": "skills/ctf-programming/SKILL.md",
    "jail": "skills/ctf-jail/SKILL.md",
    "stego": "skills/ctf-stego/SKILL.md",
    "osint": "skills/ctf-osint/SKILL.md",
    "mobile": "skills/ctf-mobile/SKILL.md",
    "malware": "skills/ctf-malware/SKILL.md",
    "web3": "skills/ctf-web3/SKILL.md",
    "cloud": "skills/ctf-cloud/SKILL.md",
    "container": "skills/ctf-container/SKILL.md",
    "ai-ml": "skills/ctf-ai-ml/SKILL.md",
    "hardware-rf": "skills/ctf-hardware-rf/SKILL.md",
    "side-channel": "skills/ctf-side-channel/SKILL.md",
    "hybrid": "skills/ctf-hybrid-chain/SKILL.md",
}

REFERENCE_DIGEST_FOR_CATEGORY = {
    "web": "docs/reference-digests/web.md",
    "pwn": "docs/reference-digests/pwn.md",
    "rev": "docs/reference-digests/rev.md",
    "crypto": "docs/reference-digests/crypto.md",
    "forensics": "docs/reference-digests/forensics.md",
    "misc": "docs/reference-digests/misc.md",
    "programming": "docs/reference-digests/programming.md",
    "jail": "docs/reference-digests/jail.md",
    "stego": "docs/reference-digests/stego.md",
    "osint": "docs/reference-digests/osint.md",
    "mobile": "docs/reference-digests/mobile.md",
    "malware": "docs/reference-digests/malware.md",
    "web3": "docs/reference-digests/web3.md",
    "cloud": "docs/reference-digests/cloud-container.md",
    "container": "docs/reference-digests/cloud-container.md",
    "ai-ml": "docs/reference-digests/ai-ml.md",
    "hardware-rf": "docs/reference-digests/hardware-rf-side-channel.md",
    "side-channel": "docs/reference-digests/hardware-rf-side-channel.md",
    "hybrid": "docs/reference-digests/hybrid.md",
}

REFERENCE_INDEX_FOR_CATEGORY = {
    "web": "docs/reference-index/web.json",
    "pwn": "docs/reference-index/pwn.json",
    "rev": "docs/reference-index/rev.json",
    "crypto": "docs/reference-index/crypto.json",
    "forensics": "docs/reference-index/forensics.json",
    "misc": "docs/reference-index/misc.json",
    "programming": "docs/reference-index/programming.json",
    "jail": "docs/reference-index/jail.json",
    "stego": "docs/reference-index/stego.json",
    "osint": "docs/reference-index/osint.json",
    "mobile": "docs/reference-index/mobile.json",
    "malware": "docs/reference-index/malware.json",
    "web3": "docs/reference-index/web3.json",
    "cloud": "docs/reference-index/cloud-container.json",
    "container": "docs/reference-index/cloud-container.json",
    "ai-ml": "docs/reference-index/ai-ml.json",
    "hardware-rf": "docs/reference-index/hardware-rf-side-channel.json",
    "side-channel": "docs/reference-index/hardware-rf-side-channel.json",
    "hybrid": "docs/reference-index/hybrid.json",
}


def fail(message: str, code: int = 2) -> None:
    print(f"level3_orchestrator: {message}", file=sys.stderr)
    raise SystemExit(code)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def utc_stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def challenge_dir_arg(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    path = path.resolve()
    try:
        path.relative_to(ROOT)
    except ValueError:
        fail(f"challenge directory must stay inside workspace root: {path}")
    if not path.is_dir():
        fail(f"challenge directory does not exist: {path}")
    if not (path / "state.json").is_file():
        fail(f"missing state.json in challenge directory: {path}")
    return path


def relative_to_challenge(challenge_dir: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(challenge_dir.resolve()).as_posix()
    except ValueError:
        fail(f"path must stay inside challenge directory: {path}")


def validate_relative_path(challenge_dir: Path, value: str, *, must_exist: bool = True) -> Path:
    if not isinstance(value, str) or not value.strip():
        fail("evidence path entries must be non-empty strings")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        fail(f"path must be challenge-relative and non-escaping: {value!r}")
    path = challenge_dir / relative
    if must_exist and not path.exists():
        fail(f"referenced artifact does not exist: {value}")
    return path


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing JSON file: {path}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: {exc}")
    if not isinstance(data, dict):
        fail(f"JSON root must be an object: {path}")
    return data


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def append_run_log(challenge_dir: Path, event: str, data: dict[str, Any]) -> None:
    path = challenge_dir / "work" / RUN_LOG
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": utc_now(),
        "event": event,
        "challenge": relative_to_challenge(ROOT, challenge_dir),
        "data": data,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, ensure_ascii=True) + "\n")


def load_state(challenge_dir: Path) -> dict[str, Any]:
    return read_json(challenge_dir / "state.json")


def save_state(challenge_dir: Path, state: dict[str, Any]) -> None:
    state["updated_at"] = utc_now()
    write_json(challenge_dir / "state.json", state)


def metadata(state: dict[str, Any]) -> dict[str, Any]:
    value = state.setdefault("metadata", {})
    if not isinstance(value, dict):
        value = {}
        state["metadata"] = value
    return value


def load_level3(challenge_dir: Path) -> dict[str, Any]:
    path = challenge_dir / "work" / STATE_NAME
    return read_json(path)


def save_level3(challenge_dir: Path, data: dict[str, Any]) -> None:
    data["updated_at"] = utc_now()
    write_json(challenge_dir / "work" / STATE_NAME, data)


def run_command(args: list[str], cwd: Path = ROOT) -> dict[str, Any]:
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)
    return {
        "command": args,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "ok": result.returncode == 0,
    }


def output_summary(result: dict[str, Any], *, lines: int = 8) -> list[str]:
    text = "\n".join([str(result.get("stdout", "")), str(result.get("stderr", ""))]).strip()
    return text.splitlines()[-lines:] if text else []


def ensure_level3_files(challenge_dir: Path) -> None:
    work = challenge_dir / "work"
    evidence = challenge_dir / "evidence"
    work.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=True)


def category_for(state: dict[str, Any], override: str | None) -> str:
    category = (override or str(state.get("category") or "")).strip()
    if not category:
        fail("category is required; set state.category or pass --category")
    category = CATEGORY_ALIASES.get(category, category)
    if category not in CATEGORY_WORKERS:
        supported = ", ".join(sorted(CATEGORY_WORKERS))
        fail(f"unsupported category {category!r}; supported categories: {supported}")
    return category


def strategy_for(category: str, worker: str) -> dict[str, list[str]]:
    if worker in COMMON_STRATEGIES:
        return {key: list(value) for key, value in COMMON_STRATEGIES[worker].items()}
    if category not in CATEGORY_DEFAULT_STRATEGIES:
        fail(f"missing Level 3 strategy profile for category: {category}")
    base = CATEGORY_DEFAULT_STRATEGIES[category]
    strategy = {key: list(value) for key, value in base.items()}
    override = WORKER_STRATEGY_OVERRIDES.get(category, {}).get(worker)
    if override:
        for key, values in override.items():
            strategy[key] = list(values)
    return strategy


def reference_digest_for(category: str) -> str:
    return REFERENCE_DIGEST_FOR_CATEGORY.get(category, "docs/reference-digests/common.md")


def reference_index_for(category: str) -> str:
    return REFERENCE_INDEX_FOR_CATEGORY.get(category, "docs/reference-index/common.json")


def reference_query_category_for(category: str) -> str:
    return Path(reference_index_for(category)).stem


def digest_pattern_summary(digest_path: str, *, limit: int = 8) -> list[str]:
    path = ROOT / digest_path
    if not path.is_file():
        return [f"missing digest: {digest_path}"]
    text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    in_patterns = False
    bullets: list[str] = []
    for line in text:
        stripped = line.strip()
        if stripped == "## CTF-Relevant Patterns":
            in_patterns = True
            continue
        if in_patterns and stripped.startswith("## "):
            break
        if in_patterns and stripped.startswith("- "):
            bullets.append(stripped)
            if len(bullets) >= limit:
                break
    return bullets or [f"read {digest_path} before probing"]


def active_worker_count(level3: dict[str, Any]) -> int:
    return sum(
        1
        for task in level3.get("workers", [])
        if isinstance(task, dict) and task.get("status") in ACTIVE_TASK_STATUSES
    )


def command_init(args: argparse.Namespace) -> int:
    challenge_dir = challenge_dir_arg(args.challenge_dir)
    ensure_level3_files(challenge_dir)
    state = load_state(challenge_dir)
    category = category_for(state, args.category)

    preflight = run_command(["python3", "tools/preflight_check.py", "--strict-optional"])
    proof = run_command(["python3", "tools/proof_validate.py", relative_to_challenge(ROOT, challenge_dir)])

    now = utc_now()
    level3 = {
        "schema_version": 3,
        "level3_versions": ["v1_packets", "v2_multi_agent_dispatch", "v3_category_strategy"],
        "created_at": now,
        "updated_at": now,
        "status": "initialized",
        "category": category,
        "runtime": {
            "orchestrator": "tools/level3_orchestrator.py",
            "dispatch_tool_contract": "multi_agent_v1.spawn_agent",
            "dispatch_owner": "Codex main agent",
            "merge_owner": "tools/level3_orchestrator.py collect|merge",
        },
        "challenge": {
            "path": relative_to_challenge(ROOT, challenge_dir),
            "event": state.get("event", ""),
            "category": state.get("category", ""),
            "name": state.get("name", ""),
        },
        "inputs": {
            "state": "state.json",
            "notes": "notes.md",
            "skill": SKILL_FOR_CATEGORY.get(category, "skills/ctf-misc/SKILL.md"),
            "solve_playbook": "docs/CTF_SOLVE_PLAYBOOKS.md",
            "reference_digest": reference_digest_for(category),
            "reference_index": reference_index_for(category),
            "reference_query_category": reference_query_category_for(category),
            "reference_query_tool": "tools/reference_query.py",
            "memory": "docs/CTF_SOLVER_MEMORY.md",
            "handoff": "docs/LEVEL2_TO_LEVEL3_HANDOFF.md",
        },
        "level0_2": {
            "preflight": {
                "ok": preflight["ok"],
                "returncode": preflight["returncode"],
                "summary": output_summary(preflight),
            },
            "proof": {
                "ok": proof["ok"],
                "returncode": proof["returncode"],
                "summary": output_summary(proof),
            },
        },
        "budgets": {
            "requests": args.budget_requests,
            "seconds": args.budget_seconds,
            "mutations": args.budget_mutations,
        },
        "stop_conditions": [
            "flag recovered and proof_validate passes",
            "remote expired or unavailable",
            "all assigned workers exhausted their budgets",
            "human stop",
        ],
        "workers": [],
        "merged": {
            "facts": [],
            "negative_results": [],
            "mutations": [],
            "artifacts": [],
        },
        "score": {
            "value": 0,
            "checks": [],
        },
    }
    save_level3(challenge_dir, level3)

    meta = metadata(state)
    meta["level3_status"] = "initialized"
    meta["level3_version"] = "v3_category_strategy"
    meta["level3_state"] = f"work/{STATE_NAME}"
    meta["level3_run_log"] = f"work/{RUN_LOG}"
    meta["level3_workers_active"] = 0
    save_state(challenge_dir, state)
    append_run_log(
        challenge_dir,
        "init",
        {"category": category, "preflight_ok": preflight["ok"], "proof_ok": proof["ok"]},
    )

    print(challenge_dir / "work" / STATE_NAME)
    return 0 if preflight["ok"] and proof["ok"] else 1


def task_for(
    *,
    challenge_dir: Path,
    category: str,
    worker: str,
    objective: str,
    index: int,
    budgets: dict[str, Any],
) -> dict[str, Any]:
    task_id = f"{category}-{index:02d}-{worker}"
    strategy = strategy_for(category, worker)
    return {
        "id": task_id,
        "worker": worker,
        "category": category,
        "status": "pending",
        "objective": objective,
        "strategy": strategy,
        "multi_agent": {
            "spawn_tool": "multi_agent_v1.spawn_agent",
            "parallel_safe": True,
            "orchestrator_merge_required": True,
            "result_contract": "write JSON matching expected_output, then main agent runs collect/merge",
        },
        "inputs": {
            "challenge_dir": relative_to_challenge(ROOT, challenge_dir),
            "state": "state.json",
            "notes": "notes.md",
            "skill": SKILL_FOR_CATEGORY.get(category, "skills/ctf-misc/SKILL.md"),
            "solve_playbook": "docs/CTF_SOLVE_PLAYBOOKS.md",
            "reference_digest": reference_digest_for(category),
            "reference_index": reference_index_for(category),
            "reference_query_category": reference_query_category_for(category),
            "reference_query_tool": "tools/reference_query.py",
            "attempt_matrix": f"work/{ATTEMPT_MATRIX}",
            "mutation_ledger": f"work/{MUTATION_LEDGER}",
            "level3_state": f"work/{STATE_NAME}",
        },
        "budget": budgets,
        "avoid": [
            "Do not repeat rows already present in work/ATTEMPT_MATRIX.md unless new evidence changes the hypothesis.",
            "Do not mutate remote state without writing a mutation entry.",
            "Do not declare solved; submit evidence for orchestrator merge and proof validation.",
            "Do not run remote_live or remote_live_exploit replay unless the operator explicitly approved it.",
        ],
        "expected_output": {
            "worker": worker,
            "status": "PASS|FAIL|INCONCLUSIVE",
            "facts": [],
            "negative_results": [],
            "mutations": [],
            "artifacts": [],
            "next_hypotheses": [],
            "reference_queries": [],
            "reference_files_consulted": [],
            "read_receipts": {
                "skill_read": SKILL_FOR_CATEGORY.get(category, "skills/ctf-misc/SKILL.md"),
                "solve_playbook_read": "docs/CTF_SOLVE_PLAYBOOKS.md",
                "reference_digest_read": reference_digest_for(category),
                "rules_applied": [],
                "evidence_contract_used": [],
            },
            "stop_reason": "",
        },
        "evidence_required": strategy.get("evidence_required", []),
        "failure_modes": strategy.get("failure_modes", []),
        "artifact_path": f"evidence/level3_worker_{worker}.md",
    }


def ensure_markdown_headers(challenge_dir: Path) -> None:
    matrix = challenge_dir / "work" / ATTEMPT_MATRIX
    if not matrix.exists():
        matrix.write_text(
            "# Level 3 Attempt Matrix\n\n"
            "| Worker | Result | Target | Input Shape | Evidence |\n"
            "| --- | --- | --- | --- | --- |\n",
            encoding="utf-8",
        )
    ledger = challenge_dir / "work" / MUTATION_LEDGER
    if not ledger.exists():
        ledger.write_text(
            "# Level 3 Mutation Ledger\n\n"
            "| Worker | Target | Action | Before | After | Evidence |\n"
            "| --- | --- | --- | --- | --- | --- |\n",
            encoding="utf-8",
        )


def command_plan(args: argparse.Namespace) -> int:
    challenge_dir = challenge_dir_arg(args.challenge_dir)
    level3 = load_level3(challenge_dir)
    state = load_state(challenge_dir)
    category = category_for(state, args.category or str(level3.get("category") or ""))
    ensure_markdown_headers(challenge_dir)

    budgets = {
        "requests": args.budget_requests if args.budget_requests is not None else level3["budgets"]["requests"],
        "seconds": args.budget_seconds if args.budget_seconds is not None else level3["budgets"]["seconds"],
        "mutations": args.budget_mutations if args.budget_mutations is not None else level3["budgets"]["mutations"],
    }
    roles = COMMON_WORKERS + CATEGORY_WORKERS[category]
    tasks = [
        task_for(
            challenge_dir=challenge_dir,
            category=category,
            worker=worker,
            objective=objective,
            index=index,
            budgets=budgets,
        )
        for index, (worker, objective) in enumerate(roles, start=1)
    ]

    tasks_path = challenge_dir / "work" / TASKS_NAME
    write_json(tasks_path, {"schema_version": 1, "category": category, "tasks": tasks})
    level3["category"] = category
    level3["status"] = "planned"
    level3["budgets"] = budgets
    level3["workers"] = tasks
    save_level3(challenge_dir, level3)

    meta = metadata(state)
    meta["level3_status"] = "planned"
    meta["level3_version"] = "v3_category_strategy"
    meta["level3_tasks"] = f"work/{TASKS_NAME}"
    meta["level3_attempt_matrix"] = f"work/{ATTEMPT_MATRIX}"
    meta["level3_mutation_ledger"] = f"work/{MUTATION_LEDGER}"
    meta["level3_workers_active"] = len(tasks)
    save_state(challenge_dir, state)
    append_run_log(
        challenge_dir,
        "plan",
        {"category": category, "workers": [task["worker"] for task in tasks], "budgets": budgets},
    )

    print(tasks_path)
    return 0


def find_task(level3: dict[str, Any], worker: str) -> dict[str, Any]:
    for task in level3.get("workers", []):
        if isinstance(task, dict) and task.get("worker") == worker:
            return task
    fail(f"unknown worker: {worker}")


def render_task_packet(task: dict[str, Any]) -> str:
    inputs = task.get("inputs") if isinstance(task.get("inputs"), dict) else {}
    digest = str(inputs.get("reference_digest") or "")
    index = str(inputs.get("reference_index") or "")
    query_category = str(inputs.get("reference_query_category") or task.get("category") or "common")
    query_tool = str(inputs.get("reference_query_tool") or "tools/reference_query.py")
    digest_lines = digest_pattern_summary(digest) if digest else ["no reference digest configured"]
    return "\n".join(
        [
            f"# Level 3 Worker Packet: {task['worker']}",
            "",
            "You are a bounded CTF Level 3 worker. Work inside the assigned challenge only.",
            "Before probing, read task.inputs.skill, task.inputs.solve_playbook, task.inputs.reference_digest, and task.inputs.reference_index, then use the embedded strategy profile.",
            "Use task.inputs.reference_query_tool only after you have challenge evidence text, file names, versions, errors, constants, APIs, opcodes, or transcripts to query against.",
            "Report only evidence-backed facts and negatives.",
            "Do not declare the challenge solved. Return JSON matching expected_output.",
            "The returned JSON must include read_receipts, reference_queries, and reference_files_consulted.",
            "Do not run remote_live or remote_live_exploit replay without explicit operator approval.",
            "",
            "## Reference Digest Summary",
            "",
            f"- digest: `{digest or 'none'}`",
            f"- index: `{index or 'none'}`",
            f"- query_tool: `{query_tool}`",
            *digest_lines,
            "",
            "## Evidence-Gated Reference Query",
            "",
            f"- command: `python3 {query_tool} --category {query_category} --evidence <evidence-file-or-text> --limit 8 --json`",
            "- consult exact files from the query result only when they match current challenge evidence",
            "- record every query in `reference_queries` and every opened local reference in `reference_files_consulted`",
            "",
            "```json",
            json.dumps(task, indent=2, sort_keys=True),
            "```",
            "",
        ]
    )


def command_packet(args: argparse.Namespace) -> int:
    challenge_dir = challenge_dir_arg(args.challenge_dir)
    level3 = load_level3(challenge_dir)
    task = find_task(level3, args.worker)
    print(render_task_packet(task), end="")
    return 0


def select_dispatch_tasks(level3: dict[str, Any], workers: list[str], limit: int | None, include_dispatched: bool) -> list[dict[str, Any]]:
    allowed_statuses = {"pending", "dispatched"} if include_dispatched else {"pending"}
    selected: list[dict[str, Any]] = []
    worker_filter = set(workers)
    for task in level3.get("workers", []):
        if not isinstance(task, dict):
            continue
        if worker_filter and task.get("worker") not in worker_filter:
            continue
        if task.get("status") not in allowed_statuses:
            continue
        selected.append(task)
        if limit is not None and len(selected) >= limit:
            break
    if workers:
        found = {str(task.get("worker")) for task in selected}
        missing = sorted(set(workers) - found)
        if missing:
            fail(f"workers not dispatchable with current filters: {', '.join(missing)}")
    return selected


def command_dispatch(args: argparse.Namespace) -> int:
    challenge_dir = challenge_dir_arg(args.challenge_dir)
    level3 = load_level3(challenge_dir)
    state = load_state(challenge_dir)
    workers = [item.strip() for item in (args.workers or "").split(",") if item.strip()]
    selected = select_dispatch_tasks(level3, workers, args.limit, args.include_dispatched)
    if not selected:
        fail("no pending worker tasks to dispatch")

    dispatch_id = f"dispatch-{utc_stamp()}"
    dispatch_dir = challenge_dir / "work" / DISPATCH_DIR
    dispatch_dir.mkdir(parents=True, exist_ok=True)
    manifest_tasks: list[dict[str, Any]] = []
    for task in selected:
        packet_rel = f"work/{DISPATCH_DIR}/{task['id']}.md"
        packet_path = challenge_dir / packet_rel
        task["status"] = "dispatched"
        task["dispatch"] = {
            "id": dispatch_id,
            "packet": packet_rel,
            "spawn_tool": "multi_agent_v1.spawn_agent",
            "spawn_status": "ready",
            "assigned_agent_id": None,
            "dispatched_at": utc_now(),
        }
        packet_path.write_text(render_task_packet(task), encoding="utf-8")
        manifest_tasks.append(
            {
                "task_id": task["id"],
                "worker": task["worker"],
                "category": task["category"],
                "packet": packet_rel,
                "spawn_tool": "multi_agent_v1.spawn_agent",
                "spawn_prompt": (
                    f"Use the Level 3 packet at {packet_rel}. Work only inside "
                    f"{task['inputs']['challenge_dir']}. Read the packet's skill, solve_playbook, reference_digest, and reference_index inputs "
                    "before probing. Query local references only after evidence exists. Return a JSON result file under work/."
                ),
                "expected_result": task["expected_output"],
            }
        )

    manifest = {
        "schema_version": 1,
        "dispatch_id": dispatch_id,
        "created_at": utc_now(),
        "challenge": relative_to_challenge(ROOT, challenge_dir),
        "mode": "spawn_agent_ready",
        "spawn_tool": "multi_agent_v1.spawn_agent",
        "tasks": manifest_tasks,
        "merge_command": f"python3 tools/level3_orchestrator.py collect {relative_to_challenge(ROOT, challenge_dir)} work/level3_results",
    }
    manifest_path = challenge_dir / "work" / DISPATCH_NAME
    write_json(manifest_path, manifest)
    markdown_path = challenge_dir / "work" / DISPATCH_MARKDOWN
    lines = [
        "# Level 3 Multi-Agent Dispatch",
        "",
        f"- dispatch_id: `{dispatch_id}`",
        f"- spawn_tool: `multi_agent_v1.spawn_agent`",
        f"- challenge: `{relative_to_challenge(ROOT, challenge_dir)}`",
        "",
        "Run one sub-agent per row when parallel delegation is available. After workers return JSON, place results under `work/level3_results/` and run the merge command.",
        "",
        "| Worker | Packet | Spawn Prompt |",
        "| --- | --- | --- |",
    ]
    for item in manifest_tasks:
        lines.append(f"| {md_escape(item['worker'])} | `{item['packet']}` | {md_escape(item['spawn_prompt'])} |")
    lines.extend(["", f"Merge command: `{manifest['merge_command']}`", ""])
    markdown_path.write_text("\n".join(lines), encoding="utf-8")

    level3["status"] = "dispatched"
    level3["last_dispatch"] = {
        "id": dispatch_id,
        "manifest": f"work/{DISPATCH_NAME}",
        "markdown": f"work/{DISPATCH_MARKDOWN}",
        "task_count": len(manifest_tasks),
    }
    save_level3(challenge_dir, level3)

    meta = metadata(state)
    meta["level3_status"] = "dispatched"
    meta["level3_dispatch"] = f"work/{DISPATCH_NAME}"
    meta["level3_dispatch_batch"] = dispatch_id
    meta["level3_workers_active"] = active_worker_count(level3)
    save_state(challenge_dir, state)
    append_run_log(
        challenge_dir,
        "dispatch",
        {"dispatch_id": dispatch_id, "workers": [item["worker"] for item in manifest_tasks], "task_count": len(manifest_tasks)},
    )

    print(relative_to_challenge(challenge_dir, manifest_path))
    return 0


def command_assign(args: argparse.Namespace) -> int:
    challenge_dir = challenge_dir_arg(args.challenge_dir)
    level3 = load_level3(challenge_dir)
    task = find_task(level3, args.worker)
    dispatch = task.setdefault("dispatch", {})
    if not isinstance(dispatch, dict):
        dispatch = {}
        task["dispatch"] = dispatch
    task["status"] = "dispatched"
    dispatch["spawn_tool"] = "multi_agent_v1.spawn_agent"
    dispatch["spawn_status"] = args.status
    dispatch["assigned_agent_id"] = args.agent_id
    dispatch["assigned_at"] = utc_now()
    if args.note:
        dispatch["note"] = args.note
    level3["status"] = "dispatched"
    save_level3(challenge_dir, level3)

    state = load_state(challenge_dir)
    meta = metadata(state)
    meta["level3_status"] = "dispatched"
    meta["level3_workers_active"] = active_worker_count(level3)
    save_state(challenge_dir, state)
    append_run_log(
        challenge_dir,
        "assign",
        {"worker": args.worker, "agent_id": args.agent_id, "status": args.status},
    )
    print(json.dumps({"worker": args.worker, "agent_id": args.agent_id, "status": args.status}, indent=2, sort_keys=True))
    return 0


def collect_evidence_paths(challenge_dir: Path, items: Any) -> list[str]:
    paths: list[str] = []
    if isinstance(items, str):
        items = [items]
    if not isinstance(items, list):
        return paths
    for value in items:
        if isinstance(value, str):
            paths.append(relative_to_challenge(challenge_dir, validate_relative_path(challenge_dir, value)))
    return paths


def evidence_from_entry(challenge_dir: Path, entry: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("evidence", "artifacts"):
        values.extend(collect_evidence_paths(challenge_dir, entry.get(key, [])))
    return list(dict.fromkeys(values))


def require_receipt_value(receipts: dict[str, Any], key: str, expected: str) -> None:
    actual = receipts.get(key)
    if not isinstance(actual, str) or actual.strip() != expected:
        fail(f"read_receipts.{key} must equal {expected!r}")


def validate_reference_queries(task: dict[str, Any], result: dict[str, Any]) -> None:
    inputs = task.get("inputs") if isinstance(task.get("inputs"), dict) else {}
    expected_category = str(inputs.get("reference_query_category") or task.get("category") or "")
    queries = result.get("reference_queries")
    if not isinstance(queries, list) or not queries:
        fail("worker result requires non-empty reference_queries")
    for query in queries:
        if not isinstance(query, dict):
            fail("reference_queries entries must be objects")
        if not isinstance(query.get("query"), str) or not query.get("query", "").strip():
            fail("reference_queries entries require query")
        category = query.get("category")
        if not isinstance(category, str) or category.strip() != expected_category:
            fail(f"reference_queries.category must equal {expected_category!r}")
        status = query.get("status")
        if not isinstance(status, str) or status.strip() not in {"matched", "no_match", "skipped"}:
            fail("reference_queries.status must be matched, no_match, or skipped")


def validate_reference_files(result: dict[str, Any]) -> None:
    consulted = result.get("reference_files_consulted")
    if not isinstance(consulted, list):
        fail("worker result requires reference_files_consulted list")
    cache_root = (ROOT / ".cache" / "references").resolve()
    for item in consulted:
        if not isinstance(item, dict):
            fail("reference_files_consulted entries must be objects")
        for key in ("category", "ref_id", "entry_id", "path", "reason"):
            if not isinstance(item.get(key), str) or not item.get(key, "").strip():
                fail(f"reference_files_consulted entries require {key}")
        path_value = Path(str(item["path"]))
        if path_value.is_absolute() or ".." in path_value.parts:
            fail(f"reference file path must be workspace-relative and non-escaping: {item['path']!r}")
        path = (ROOT / path_value).resolve()
        try:
            path.relative_to(cache_root)
        except ValueError:
            fail(f"reference file path must stay under .cache/references: {item['path']!r}")
        if not path.is_file():
            fail(f"reference file does not exist: {item['path']}")
        line_start = item.get("line_start")
        line_end = item.get("line_end")
        if not isinstance(line_start, int) or not isinstance(line_end, int) or line_start < 1 or line_end < line_start:
            fail("reference_files_consulted line_start/line_end must be positive integers")


def validate_worker_result(challenge_dir: Path, task: dict[str, Any], result: dict[str, Any]) -> None:
    worker = result.get("worker")
    if not isinstance(worker, str) or not worker.strip():
        fail("worker result requires non-empty worker")
    status = result.get("status")
    if status not in ALLOWED_WORKER_STATUSES:
        fail(f"worker status must be one of {', '.join(sorted(ALLOWED_WORKER_STATUSES))}")
    inputs = task.get("inputs")
    if not isinstance(inputs, dict):
        fail("task inputs are missing")
    receipts = result.get("read_receipts")
    if not isinstance(receipts, dict):
        fail("worker result requires read_receipts")
    require_receipt_value(receipts, "skill_read", str(inputs.get("skill") or ""))
    require_receipt_value(receipts, "solve_playbook_read", str(inputs.get("solve_playbook") or ""))
    require_receipt_value(receipts, "reference_digest_read", str(inputs.get("reference_digest") or ""))
    rules = receipts.get("rules_applied")
    if not isinstance(rules, list) or not all(isinstance(item, str) and item.strip() for item in rules):
        fail("read_receipts.rules_applied must be a non-empty list of strings")
    evidence_contract = receipts.get("evidence_contract_used")
    if not isinstance(evidence_contract, list) or not all(isinstance(item, str) and item.strip() for item in evidence_contract):
        fail("read_receipts.evidence_contract_used must be a non-empty list of strings")
    validate_reference_queries(task, result)
    validate_reference_files(result)

    for fact in result.get("facts", []):
        if not isinstance(fact, dict):
            fail("facts entries must be objects")
        if not str(fact.get("claim", "")).strip():
            fail("fact entries require claim")
        if not evidence_from_entry(challenge_dir, fact):
            fail("fact entries require existing evidence or artifacts")

    for negative in result.get("negative_results", []):
        if not isinstance(negative, dict):
            fail("negative_results entries must be objects")
        if not str(negative.get("input_shape", "")).strip():
            fail("negative_results entries require input_shape")
        if not str(negative.get("result_class", "")).strip():
            fail("negative_results entries require result_class")
        if not evidence_from_entry(challenge_dir, negative):
            fail("negative_results entries require existing evidence or artifacts")

    for mutation in result.get("mutations", []):
        if not isinstance(mutation, dict):
            fail("mutations entries must be objects")
        if not str(mutation.get("target", "")).strip() or not str(mutation.get("action", "")).strip():
            fail("mutations require target and action")
        if not evidence_from_entry(challenge_dir, mutation):
            fail("mutations require existing evidence or artifacts")

    collect_evidence_paths(challenge_dir, result.get("artifacts", []))


def md_escape(value: object) -> str:
    return str(value if value is not None else "").replace("\n", " ").replace("|", "\\|").strip()


def append_unique_line(path: Path, line: str) -> None:
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    if line not in text:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)


def write_worker_summary(challenge_dir: Path, result: dict[str, Any]) -> str:
    worker = str(result["worker"])
    receipts = result.get("read_receipts") if isinstance(result.get("read_receipts"), dict) else {}
    summary_path = challenge_dir / "evidence" / f"level3_worker_{worker}_{utc_stamp()}.md"
    lines = [
        f"# Level 3 Worker Result: {worker}",
        "",
        f"- status: `{result['status']}`",
        f"- stop_reason: `{md_escape(result.get('stop_reason', ''))}`",
        f"- skill_read: `{md_escape(receipts.get('skill_read', ''))}`",
        f"- solve_playbook_read: `{md_escape(receipts.get('solve_playbook_read', ''))}`",
        f"- reference_digest_read: `{md_escape(receipts.get('reference_digest_read', ''))}`",
        "",
        "## Reference Queries",
    ]
    for query in result.get("reference_queries", []):
        if isinstance(query, dict):
            lines.append(
                f"- {md_escape(query.get('category'))}: {md_escape(query.get('query'))} "
                f"status={md_escape(query.get('status'))} count={md_escape(query.get('result_count', ''))}"
            )
    lines.extend(["", "## Reference Files Consulted"])
    for item in result.get("reference_files_consulted", []):
        if isinstance(item, dict):
            lines.append(
                f"- {md_escape(item.get('entry_id'))}: `{md_escape(item.get('path'))}` "
                f"lines={md_escape(item.get('line_start'))}-{md_escape(item.get('line_end'))}"
            )
    lines.extend([
        "",
        "## Facts",
    ])
    for fact in result.get("facts", []):
        lines.append(f"- {md_escape(fact.get('claim'))} evidence={', '.join(evidence_from_entry(challenge_dir, fact))}")
    lines.extend(["", "## Negative Results"])
    for negative in result.get("negative_results", []):
        lines.append(
            f"- {md_escape(negative.get('target'))}: {md_escape(negative.get('input_shape'))} -> "
            f"{md_escape(negative.get('result_class'))}"
        )
    lines.extend(["", "## Mutations"])
    for mutation in result.get("mutations", []):
        lines.append(
            f"- {md_escape(mutation.get('target'))}: {md_escape(mutation.get('action'))} "
            f"before={md_escape(mutation.get('before'))} after={md_escape(mutation.get('after'))}"
        )
    lines.append("")
    summary_path.write_text("\n".join(lines), encoding="utf-8")
    return relative_to_challenge(challenge_dir, summary_path)


def append_attempt_matrix(challenge_dir: Path, result: dict[str, Any], summary_rel: str) -> None:
    matrix = challenge_dir / "work" / ATTEMPT_MATRIX
    ensure_markdown_headers(challenge_dir)
    worker = result["worker"]
    for fact in result.get("facts", []):
        evidence = ", ".join(evidence_from_entry(challenge_dir, fact) or [summary_rel])
        line = (
            f"| {md_escape(worker)} | CONFIRMED | {md_escape(fact.get('target', 'fact'))} | "
            f"{md_escape(fact.get('claim'))} | {md_escape(evidence)} |\n"
        )
        append_unique_line(matrix, line)
    for negative in result.get("negative_results", []):
        evidence = ", ".join(evidence_from_entry(challenge_dir, negative) or [summary_rel])
        result_class = str(negative.get("result_class") or "NEGATIVE").upper()
        if result_class not in RESULT_CLASSES:
            result_class = "NEGATIVE"
        line = (
            f"| {md_escape(worker)} | {result_class} | {md_escape(negative.get('target', 'unknown'))} | "
            f"{md_escape(negative.get('input_shape'))} | {md_escape(evidence)} |\n"
        )
        append_unique_line(matrix, line)


def append_mutation_ledger(challenge_dir: Path, result: dict[str, Any], summary_rel: str) -> None:
    ledger = challenge_dir / "work" / MUTATION_LEDGER
    ensure_markdown_headers(challenge_dir)
    worker = result["worker"]
    for mutation in result.get("mutations", []):
        evidence = ", ".join(evidence_from_entry(challenge_dir, mutation) or [summary_rel])
        line = (
            f"| {md_escape(worker)} | {md_escape(mutation.get('target'))} | "
            f"{md_escape(mutation.get('action'))} | {md_escape(mutation.get('before', 'unknown'))} | "
            f"{md_escape(mutation.get('after', 'unknown'))} | {md_escape(evidence)} |\n"
        )
        append_unique_line(ledger, line)


def update_notes(challenge_dir: Path, result: dict[str, Any], summary_rel: str) -> None:
    notes = challenge_dir / "notes.md"
    if not notes.exists():
        notes.write_text("# Challenge Notes\n", encoding="utf-8")
    with notes.open("a", encoding="utf-8") as handle:
        handle.write("\n## Level 3 Merge\n\n")
        handle.write(f"- timestamp: `{utc_now()}`\n")
        handle.write(f"- worker: `{result['worker']}`\n")
        handle.write(f"- status: `{result['status']}`\n")
        handle.write(f"- summary: `{summary_rel}`\n")


def merge_worker_result(challenge_dir: Path, level3: dict[str, Any], result_path: Path) -> str:
    result = read_json(result_path)
    worker_value = result.get("worker")
    if not isinstance(worker_value, str) or not worker_value.strip():
        fail("worker result requires non-empty worker")
    worker = worker_value
    task = find_task(level3, worker)
    validate_worker_result(challenge_dir, task, result)
    result_rel = relative_to_challenge(challenge_dir, result_path)
    if task.get("status") == "merged":
        if task.get("result") == result_rel and isinstance(task.get("summary"), str):
            return str(task["summary"])
        fail(f"worker already merged with a different result: {worker}")

    summary_rel = write_worker_summary(challenge_dir, result)
    append_attempt_matrix(challenge_dir, result, summary_rel)
    append_mutation_ledger(challenge_dir, result, summary_rel)
    update_notes(challenge_dir, result, summary_rel)

    merged = level3.setdefault("merged", {"facts": [], "negative_results": [], "mutations": [], "artifacts": []})
    merged.setdefault("facts", []).extend(result.get("facts", []))
    merged.setdefault("negative_results", []).extend(result.get("negative_results", []))
    merged.setdefault("mutations", []).extend(result.get("mutations", []))
    artifacts = set(merged.setdefault("artifacts", []))
    artifacts.add(summary_rel)
    for artifact in collect_evidence_paths(challenge_dir, result.get("artifacts", [])):
        artifacts.add(artifact)
    merged["artifacts"] = sorted(artifacts)
    for task in level3.get("workers", []):
        if isinstance(task, dict) and task.get("worker") == worker:
            task["status"] = "merged"
            task["result"] = result_rel
            task["summary"] = summary_rel
            dispatch = task.get("dispatch")
            if isinstance(dispatch, dict):
                dispatch["spawn_status"] = "collected"
                dispatch["collected_at"] = utc_now()
    level3["status"] = "merged"
    return summary_rel


def update_state_after_merge(challenge_dir: Path, level3: dict[str, Any]) -> None:
    save_level3(challenge_dir, level3)

    state = load_state(challenge_dir)
    evidence = state.setdefault("evidence", [])
    if not isinstance(evidence, list):
        evidence = []
        state["evidence"] = evidence
    merged = level3.setdefault("merged", {"facts": [], "negative_results": [], "mutations": [], "artifacts": []})
    artifacts = set(merged.setdefault("artifacts", []))
    for artifact in sorted(artifacts):
        if artifact not in evidence:
            evidence.append(artifact)
    meta = metadata(state)
    meta["level3_status"] = "merged"
    meta["level3_attempt_matrix"] = f"work/{ATTEMPT_MATRIX}"
    meta["level3_mutation_ledger"] = f"work/{MUTATION_LEDGER}"
    meta["level3_workers_active"] = active_worker_count(level3)
    save_state(challenge_dir, state)


def command_merge(args: argparse.Namespace) -> int:
    challenge_dir = challenge_dir_arg(args.challenge_dir)
    level3 = load_level3(challenge_dir)
    result_path = validate_relative_path(challenge_dir, args.result_json)
    summary_rel = merge_worker_result(challenge_dir, level3, result_path)
    update_state_after_merge(challenge_dir, level3)
    append_run_log(
        challenge_dir,
        "merge",
        {"result": relative_to_challenge(challenge_dir, result_path), "summary": summary_rel},
    )
    print(summary_rel)
    return 0


def collect_result_paths(challenge_dir: Path, value: str, pattern: str) -> list[Path]:
    path = validate_relative_path(challenge_dir, value, must_exist=True)
    if path.is_file():
        return [path]
    if not path.is_dir():
        fail(f"collect target is neither file nor directory: {value}")
    paths = sorted(item for item in path.glob(pattern) if item.is_file())
    if not paths:
        fail(f"no result JSON files matched {value}/{pattern}")
    return paths


def command_collect(args: argparse.Namespace) -> int:
    challenge_dir = challenge_dir_arg(args.challenge_dir)
    level3 = load_level3(challenge_dir)
    summaries: list[str] = []
    for result_path in collect_result_paths(challenge_dir, args.results, args.glob):
        summaries.append(merge_worker_result(challenge_dir, level3, result_path))
    update_state_after_merge(challenge_dir, level3)
    append_run_log(
        challenge_dir,
        "collect",
        {"results": args.results, "glob": args.glob, "summaries": summaries, "count": len(summaries)},
    )
    print(json.dumps({"merged": summaries, "count": len(summaries)}, indent=2, sort_keys=True))
    return 0


def command_status(args: argparse.Namespace) -> int:
    challenge_dir = challenge_dir_arg(args.challenge_dir)
    level3 = load_level3(challenge_dir)
    pending = [task.get("worker") for task in level3.get("workers", []) if isinstance(task, dict) and task.get("status") == "pending"]
    dispatched = [
        {
            "worker": task.get("worker"),
            "agent_id": (task.get("dispatch") or {}).get("assigned_agent_id") if isinstance(task.get("dispatch"), dict) else None,
            "spawn_status": (task.get("dispatch") or {}).get("spawn_status") if isinstance(task.get("dispatch"), dict) else None,
        }
        for task in level3.get("workers", [])
        if isinstance(task, dict) and task.get("status") == "dispatched"
    ]
    merged = [task.get("worker") for task in level3.get("workers", []) if isinstance(task, dict) and task.get("status") == "merged"]
    print(
        json.dumps(
            {
                "status": level3.get("status"),
                "category": level3.get("category"),
                "pending": pending,
                "dispatched": dispatched,
                "merged": merged,
                "score": level3.get("score", {}),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def command_evaluate(args: argparse.Namespace) -> int:
    challenge_dir = challenge_dir_arg(args.challenge_dir)
    level3 = load_level3(challenge_dir)
    state = load_state(challenge_dir)
    replay_kind = str(metadata(state).get("replay_kind") or "local")
    replay: dict[str, Any] | None = None
    if args.run_replay and replay_kind not in {"remote_live", "remote_live_exploit"}:
        replay = run_command(["python3", "tools/replay_runner.py", relative_to_challenge(ROOT, challenge_dir)])
    elif args.run_replay:
        replay = {
            "ok": True,
            "returncode": 0,
            "stdout": "",
            "stderr": f"skipped unsafe replay_kind={replay_kind}",
            "command": [],
        }

    proof = run_command(["python3", "tools/proof_validate.py", relative_to_challenge(ROOT, challenge_dir)])
    matrix_exists = (challenge_dir / "work" / ATTEMPT_MATRIX).is_file()
    ledger_exists = (challenge_dir / "work" / MUTATION_LEDGER).is_file()
    merged = level3.get("merged", {}) if isinstance(level3.get("merged"), dict) else {}
    checks = [
        {"name": "proof_validate", "ok": proof["ok"]},
        {"name": "attempt_matrix", "ok": matrix_exists},
        {"name": "mutation_ledger", "ok": ledger_exists},
        {"name": "worker_artifacts", "ok": bool(merged.get("artifacts"))},
    ]
    if replay is not None:
        checks.append({"name": "replay", "ok": replay["ok"], "summary": output_summary(replay)})
    score_value = min(100, sum(25 for check in checks if check["ok"]))
    level3["status"] = "evaluated"
    level3["score"] = {"value": score_value, "checks": checks, "proof_summary": output_summary(proof)}
    save_level3(challenge_dir, level3)

    meta = metadata(state)
    meta["level3_status"] = "evaluated"
    meta["level3_score"] = score_value
    save_state(challenge_dir, state)
    append_run_log(
        challenge_dir,
        "evaluate",
        {"score": score_value, "proof_ok": proof["ok"], "replay_kind": replay_kind, "run_replay": bool(args.run_replay)},
    )

    print(json.dumps(level3["score"], indent=2, sort_keys=True))
    return 0 if proof["ok"] and score_value >= 75 else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="initialize Level 3 state for a challenge")
    init.add_argument("challenge_dir")
    init.add_argument("--category")
    init.add_argument("--budget-requests", type=int, default=200)
    init.add_argument("--budget-seconds", type=int, default=1200)
    init.add_argument("--budget-mutations", type=int, default=20)
    init.set_defaults(func=command_init)

    plan = sub.add_parser("plan", help="create worker task packets")
    plan.add_argument("challenge_dir")
    plan.add_argument("--category")
    plan.add_argument("--budget-requests", type=int)
    plan.add_argument("--budget-seconds", type=int)
    plan.add_argument("--budget-mutations", type=int)
    plan.set_defaults(func=command_plan)

    packet = sub.add_parser("packet", help="print one worker packet for a sub-agent")
    packet.add_argument("challenge_dir")
    packet.add_argument("--worker", required=True)
    packet.set_defaults(func=command_packet)

    dispatch = sub.add_parser("dispatch", help="write multi_agent_v1.spawn_agent-ready packets and manifest")
    dispatch.add_argument("challenge_dir")
    dispatch.add_argument("--workers", help="comma-separated worker names; default dispatches pending workers in task order")
    dispatch.add_argument("--limit", type=int, help="maximum number of workers to dispatch")
    dispatch.add_argument("--include-dispatched", action="store_true", help="regenerate packets for already dispatched workers")
    dispatch.set_defaults(func=command_dispatch)

    assign = sub.add_parser("assign", help="record the sub-agent assignment for a dispatched worker")
    assign.add_argument("challenge_dir")
    assign.add_argument("--worker", required=True)
    assign.add_argument("--agent-id", required=True)
    assign.add_argument("--status", default="spawned", choices=["ready", "spawned", "running", "failed", "returned", "collected"])
    assign.add_argument("--note")
    assign.set_defaults(func=command_assign)

    merge = sub.add_parser("merge", help="merge a worker result JSON file")
    merge.add_argument("challenge_dir")
    merge.add_argument("result_json")
    merge.set_defaults(func=command_merge)

    collect = sub.add_parser("collect", help="merge one worker result JSON file or all JSON files in a result directory")
    collect.add_argument("challenge_dir")
    collect.add_argument("results")
    collect.add_argument("--glob", default="*.json")
    collect.set_defaults(func=command_collect)

    status = sub.add_parser("status", help="print Level 3 status")
    status.add_argument("challenge_dir")
    status.set_defaults(func=command_status)

    evaluate = sub.add_parser("evaluate", help="run replay/proof checks and score Level 3 artifacts")
    evaluate.add_argument("challenge_dir")
    evaluate.add_argument("--run-replay", action="store_true")
    evaluate.set_defaults(func=command_evaluate)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
