# Authoritative competition execution policy

This file is the authoritative solve policy. Precedence is: this policy, `.codex/skills/ctf-solve/SKILL.md`, the selected category playbook, `README.md`, then `AGENTS.md`. Lower documents route or specialize this contract; they do not redefine it.

## Primary contract

```text
This is a timed CTF solve, not vulnerability research,
a comprehensive security assessment, or an academic investigation.

The only primary objective is to obtain the first valid flag
as quickly as possible.

Prefer the shortest executable exploit path over complete understanding.
Exploit first, explain later.
```

Time-to-first-valid-flag outranks analysis breadth, documentation quality, reusable artifacts, clean replay, and architectural understanding. A fact is not progress merely because it is new. It is progress only when it materially improves an exploit path, eliminates a costly uncertainty, or moves the solver toward a flag.

Unless needed by the leading exploit path, do not enumerate the complete attack surface, classify every possible vulnerability, audit unrelated source, conduct generalized vulnerability research, build reusable frameworks/libraries, refactor for code quality, polish reports, fully verify before a plausible remote attempt, search for other bugs while a viable path is alive, study the whole problem structure, or document architecture. Preserve only the minimal command receipt, exploit artifact, flag provenance, and information needed for later replay.

The current user-opened Sol session owns the solve continuously from selection through flag acquisition. Preparation is an internal challenge-local preflight over only the selected identity, problem information, declared scope, source, prepared input, and service configuration. Whole-contest inventory, ranking, difficulty, and success estimates are not prerequisites or solve inputs. A sibling challenge change must not stale, rewrite, or block the selected challenge workspace.

## Required execution loop

```text
observe
→ form at most 3 concrete exploit hypotheses
→ run the cheapest decisive experiment
→ kill or promote the hypothesis
→ build the smallest working PoC
→ test locally when useful
→ move to the declared remote as soon as plausible
→ surface the flag immediately
```

Each active exploit hypothesis has only: `expected primitive`, `cheapest decisive experiment`, `success condition`, and `kill condition`. Add `reopen_condition` only when a concrete future observation would justify reopening it. Do not add a fourth active hypothesis until the current three are killed, promoted, or replaced. When the recon budget ends, state `Leading exploit path`, `Decisive next experiment`, `Kill condition`, and `Expected time to PoC` (`immediate`, `few experiments`, or `long computation`).

## Race, utility, and replacement

- Python records plans, prompt packets, events, evidence, artifacts, sandboxes, receipts, and recommendations. It never launches or supervises a model, calls a model API, changes a native child lifecycle, or submits a flag. Sol owns native delegation.
- Category templates are fallback lanes, never an authoritative attack plan. Challenge evidence chooses the branch mechanism and may replace a template immediately.
- `independent-full-solve` means: independently race for the shortest valid flag path; do not produce a comprehensive analysis, wait for siblings, or collect evidence beyond what the exploit needs.
- Tier 0 is Sol-first; Tier 1 starts two children; Tier 2 three; Tier 3 four. Tier 4 keeps useful concurrency full by replacing a stalled family. A Tier 4 replacement records why proximity did not increase and uses a genuinely different exploit mechanism, not a new research topic.
- Admission overlap is advisory at 0.95. Repeated session IDs and materially exact duplicates are denied; parallel/independent solves, alternate implementations, verification, and plateau escape remain exceptions. Requested model/reasoning are intent, not proof of pinning.

Utility is exploit-proximity-first. High-value signals include actual input control, crash/oracle, address or data leak, auth/logic bypass, arbitrary read/write, code execution, solver-linked constraint reduction, deterministic extraction progress, a working PoC, remote proof of the primitive, remote readiness, and a flag candidate. Supported facts, rejected hypotheses, decompilation, source notes, architecture understanding, generic artifacts, repeated same-family commands, and unrelated files are never sufficient by themselves for `PROGRESSING`.

- `PROGRESSING`: exploit or solver completion probability materially increased and the next one to three experiments can advance it.
- `NEEDS_SIBLING_INSIGHT`: a specific blocker can be directly resolved by existing sibling evidence.
- `BUMP_AND_RETRY`: retry the same objective once with a different decisive experiment.
- `REPLACE_ATTACK_FAMILY`: information may be increasing, but exploit proximity is not; change mechanism.
- `SOL_TAKEOVER`: a promising primitive/artifact exists, but the branch is not turning it into a PoC.
- `FLAG_PATH`: a working PoC, remote-ready exploit, deterministic solver/extractor, or flag candidate is ready for immediate priority.
- `DEAD_BRANCH`: the branch is repetitive, out of scope, broadening, or has lost an executable exploit path.
- `INSUFFICIENT_DATA`: no minimum decisive experiment has been run.

Track `exploit_proximity`, `decisive_experiment_count`, `failed_decisive_experiments`, `time_or_steps_since_proximity_increase`, `working_poc_present`, `remote_ready`, and `research_drift_detected` separately from `new_information_rate`. Research drift includes broad recon after a viable primitive, continued wide reading, analysis-only artifact growth, generalization/refactoring/framework work, three information events without proximity gain, or delaying a decisive experiment to “understand more.”

## Sol and worker priorities

Sol spends its time on core primitive reasoning, difficult exploit-chain choices, minimal PoC synthesis, takeover of promising artifacts, remote execution, and flag judgment. Sol checks or manages branches only after branch creation, an explicit blocker, exploit primitive, working artifact, plateau, flag candidate, or child termination. Do not merge low-value reports or inspect every event/checkpoint.

During work, checkpoints center on: current exploit hypothesis, decisive experiment performed, observed result, exploit-proximity change, artifact path if any, next exploit action, and kill/continue/promote. Existing schema-v1 result and evidence fields remain compatible, but completeness is not a solve objective. Publish `REMOTE_FLAG_OBTAINED`, `FLAG_CANDIDATE`, `WORKING_POC`, and the explicit `EXPLOIT_PRIMITIVE_CANDIDATE`, `EXPLOIT_PRIMITIVE_CONFIRMED`, or `EXPLOIT_PRIMITIVE_REFUTED` state before any general summary or final report. A candidate is not confirmed progress: only a positive assertion plus an appropriate negative/control receipt can confirm it. Write a final worker result when the branch ends; do not pause exploitation to polish it.

High-value events, plateaus, budget boundaries, and terminal results automatically run branch utility and append `RACE_TRANSITIONS.jsonl`. A confirmed primitive requires automatic race convergence: duplicate discovery stops or becomes PoC implementation, stalled lanes receive replacement packets, and Sol takeover to the minimal PoC/endgame is a required transition rather than narrative advice. Python records these packets and receipts; Sol alone performs native child lifecycle actions.

Elastic scheduling is opt-in for proven long-compute workloads. Ordinary recon, probing, debugging, and PoC work stay at minimum allocation. Timeout cleanup is profile-based: quick/normal commands clean by default, while bounded decompile, symbolic, fuzz, forensic, crypto, cracking, and AI slices retain the sandbox by default until explicit terminal cleanup or retention policy expiry.

The dynamic scheduler allocates compute; it does not define solve progress. Short probes and quick PoCs run immediately without repeated `resource-status`, `resource-request`, `resource-plan`, or rebalance calls. Use scheduler planning before long symbolic execution, fuzzing, forensic scans, crypto/cracking, or AI computation, then inspect progress only at bounded slices. Scheduler management must never delay solver reasoning, a minimal PoC, remote execution, or flag display. New parallel harnesses use `CTF_OS_RECOMMENDED_WORKERS`.

## Scope, isolation, and flag fast path

- Attack exactly one selected challenge and only organizer-declared targets. Declared public/private/VPN/IPv6 and tcp, udp, http(s), tls, websocket/wss, dns, ssh, grpc, and custom endpoints are valid. Cloud metadata, Docker gateways, undeclared private LANs, other challenges, and unrelated hosts remain blocked.
- Challenge input/context are read-only. Each worker has private writable `/work`, `/evidence`, and `/artifacts`. Never mount the host Docker socket/root, SSH keys, browser profiles, personal cloud credentials/kubeconfig, or personal files.
- A child may mutate only its exact branch-private service. Shared challenge service lifecycle and global scheduler resize remain Sol-only.
- Challenge-provided temporary credentials and required mutations are allowed only inside the declared challenge account/project/tenant and are logged/redacted. Personal or ambient credentials are forbidden. Unsafe AI artifacts remain sandboxed and `trust_remote_code=True` is forbidden.
- A current declared-remote observation, exact command receipt, matching candidate, and existing exploit artifact yield `SUBMISSION_RECOMMENDED`. Print the exact flag immediately, stop low-value branches, and keep at most one optional verifier. Clean replay may later reach `FULLY_VERIFIED`; it is not a precondition.
- Never submit to CTFd automatically. Human submission is the competition oracle.
