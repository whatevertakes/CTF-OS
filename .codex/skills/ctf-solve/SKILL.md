---
name: ctf-solve
description: Competition-first solve of exactly one authorized CTF challenge with the current user-opened Sol session as lead attacker and a native first-to-flag race. Use for "1번 문제 풀어라", category/name, challenge names, deep solve, or swarm requests after Intake and Triage.
---

# CTF solve — first-to-flag native race

The current user-opened Sol session is the lead attacker and race coordinator. Never run Codex or Claude from Python/a shell, call a model API, or submit a flag automatically.

## Select and start

1. Read root `AGENTS.md`, current `TRIAGE.md`, `ctf_os/resources/agent-policy.md`, and the challenge category playbook.
2. Run `uv run python -m ctf_os.agent_tools prepare-challenge '<selector>' --contest '<contest>'`.
3. Stop only for ambiguous selection, stale/missing Intake/Triage, missing contest scope, an undeclared required target, required host credential, or out-of-scope action.
4. Perform compact initial recon for at most roughly 60–90 seconds. Read priority inputs and compact state first; open raw logs/inventory only to validate a concrete hypothesis.
5. Choose Tier 0–4 and run one atomic `race-plan-start`. Omit `--branch-spec` to use the aggressive category template, or supply evidence-driven JSON. The command records prompt packets but never creates native children.

```bash
uv run python -m ctf_os.agent_tools race-plan-start '<selector>' \
  --contest '<contest>' --tier 2 --tier-reason '<compact evidence>'
```

Immediately create every admitted child through Codex runtime native delegation using its returned prompt packet, mark it RUNNING, and create its sandbox. Requested role/model/reasoning are intent only; do not claim pinning without observed evidence.

## Race tiers

- Tier 0: Sol directly solves; optionally one implementation/verifier child.
- Tier 1: two children by default plus Sol. Typical lanes: fast recon and implementation.
- Tier 2: three children plus Sol. Typical lanes: static/recon, dynamic, implementation or independent full solve.
- Tier 3: four children plus Sol across distinct attack families.
- Tier 4: terminate low-value work and replace it with a new family while keeping available concurrency full; do not merely add a fifth child.

Use the largest width the native runtime and aggregate resource budget permit. If constrained, retain exploit, deep reasoning, dynamic reproduction, broad recon, then verifier in that order.

Independent strong solvers may overlap and independently solve end-to-end. `branch-admit` is advisory at 0.95 and denies only a repeated session ID or materially exact duplicate. Purposes `independent-full-solve`, `parallel-race`, `alternate-model-role`, `alternate-implementation`, `independent-verification`, `clean-room-verification`, and `plateau-escape` are overlap exceptions. Sol may record a race-value override without user confirmation.

Sol must concurrently pursue the highest-value direct path: core exploit primitive, difficult dataflow/math, final solver synthesis, stalled branch takeover, remote exploit, or candidate judgment. Never wait as a message router.

## Live insight bus

During long work, publish `race-event-publish` events for supported facts, rejected hypotheses, exploit primitives, blockers, ready artifacts, next experiments, flag candidates, remote flags, service crashes, environment discoveries, or help requests. Publish compact facts and artifact/evidence references, never raw transcripts. `EXPLOIT_PRIMITIVE` and `FLAG_CANDIDATE` become HIGH; `REMOTE_FLAG_OBTAINED` becomes CRITICAL.

Sol calls `race-events-show` after important child checkpoints, its own bounded experiments, service crashes, flag candidates, and plateau reports. Send `race-insight-packet` output to relevant active siblings and acknowledge applied events. Preserve contradictory facts instead of overwriting them. Record user guidance with `operator-hint-save` and forward it only to related active branches.

Use `branch-utility` as advice:

- `PROGRESSING`: continue and broadcast useful findings.
- `NEEDS_SIBLING_INSIGHT`: inject the latest packet and continue.
- `BUMP_AND_RETRY`: inject discoveries and retry once with changed strategy.
- `REPLACE_ATTACK_FAMILY`: terminate the branch natively and delegate a new family.
- `SOL_TAKEOVER`: Sol takes its artifact/evidence.
- `FLAG_PATH`: prioritize resources and remote execution.
- `DEAD_BRANCH`: reclaim the slot immediately.
- `INSUFFICIENT_DATA`: collect a bounded checkpoint.

Python recommends and emits packets only. Sol owns every native child lifecycle decision. One failed exploit, breakpoint, symbolic timeout, `INCONCLUSIVE`, replay failure, or wrong initial hypothesis never ends the challenge; record it and change family.

## Category race templates

Tier 2 starts three paths:

- pwn: primitive discovery; dynamic exploit with GDB/cyclic/runtime state; independent full solve. Tier 3 adds alternate ROP/ret2libc/heap/format/race family.
- rev: deep static recovery; dynamic state oracle; independent solver construction. Tier 3 adds symbolic/alternate deobfuscation.
- web: source/dataflow; live runtime probing; independent exploit chain. Tier 3 adds alternate auth/session/serialization/template family.
- crypto: mathematical structure; small-instance/known-answer experiment; independent solver. Tier 3 adds alternate algebra/lattice/factoring.
- forensic: format/filesystem/timeline; metadata/carving/stego; independent automated extraction.
- misc: broad protocol/file recon; implementation/automation; independent full solve.
- OSINT: identity/pivot map; archive/metadata/search; independent verification.
- cloud: IAM/RBAC identity graph; runtime/API enumeration; exploit-path implementation.
- AI: model/file structure; I/O differential experiment; solver/adversarial implementation.

Swap templates immediately when evidence favors a better family.

## Execution

Create worker sandboxes only after native delegation. Challenge input and `/context` are read-only; `/work`, `/evidence`, and `/artifacts` are private and writable. A worker accesses only its assigned challenge, declared targets, branch directory, sandbox, and branch-private service.

Use `--timeout-profile quick_probe|normal_command|decompile|symbolic_slice|fuzz_slice|forensic_scan|crypto_heavy|cracking_slice|ai_inference`. Long work runs in 1800-second slices with progress artifacts/events between slices. GDB, angr, z3, Sage, fpylll, RsaCtfTool, hashcat/john, AFL++, binwalk, volatility, tshark, carving, long Python solvers, model inference, and media tooling are normal CTF tools when available.

Pwn/rev/misc sandboxes automatically support ptrace/core and permissive seccomp where required. Forensic profiles may receive loop devices and `SYS_ADMIN` for read-only mounts. AI uses NVIDIA GPU pass-through when available. Never mount the host Docker socket, host root, SSH/browser profiles, personal kubeconfig/cloud config, or personal credentials.

Sol owns the shared `challenge-service`. A child may use `branch-service-build/start/restart/reset/status/logs/inspect/stop/cleanup` only for its own branch-private instance. This is the preferred crash/fuzz loop.

Declared organizer targets may be public, private/VPN, IPv6, multi-host/port and tcp/udp/http(s)/tls/websocket/wss/dns/ssh/grpc/custom. Active scanning/exploitation stays on declared challenge targets. Public docs/packages/GitHub/artifacts and explicitly approved OAST callbacks are allowed. Metadata, Docker gateways, undeclared LANs, other challenges, and unrelated hosts remain blocked.

Challenge-provided temporary/test credentials are allowed in worker-private secret storage. Cloud enumeration, role assume/impersonation, object writes, function/workload/job creation, and required IAM/RBAC mutation are allowed inside the manifest account/project/tenant and recorded in the branch mutation ledger. Never use ambient/personal credentials. Organizer virtual OSINT accounts are allowed only in the declared domain. Unsafe AI artifacts are inspected only inside the sandbox; never use `trust_remote_code=True`.

## First flag and verification

When a branch obtains a candidate, publish it immediately. Sol validates that the target is declared, actual network observation and exact command output were preserved, the candidate matches the flag pattern, and an exploit artifact exists; then call `flag-receipt-save`.

`REMOTE_FLAG_OBTAINED` plus those checks yields `SUBMISSION_RECOMMENDED` immediately. Print:

```text
REMOTE FLAG OBTAINED
Challenge: category/name
Flag: CTF{...}
Confidence: HIGH
Source: declared remote
Receipt: flag-receipts/remote-....json
Recommendation: submit immediately
Full clean replay: not required before human submission
```

Stop low-value branches and keep at most one verifier. Do not wait for two clean replays and never submit to CTFd. The human submits while optional verification continues.

Static rev/crypto may recommend submission from a solver artifact, known-answer/target behavior, and pattern. Forensic may use source fingerprint, deterministic extraction, provenance, and pattern. One-shot tasks preserve one successful exact receipt without forced repetition. `replay` remains the route to `FULLY_VERIFIED`, not a gate to showing the flag.

Canonical order:

```text
prepare-challenge → compact recon → race-plan-start → native delegation + Sol deep solve
→ sandbox-create → live events/insight → bump/replace/takeover → exploit artifact
→ declared remote receipt → SUBMISSION_RECOMMENDED → immediate flag output
→ manual human submission → optional verifier/replay → FULLY_VERIFIED
```
