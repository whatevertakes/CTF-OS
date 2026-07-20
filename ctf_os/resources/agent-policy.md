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

The current user-opened Sol session owns the solve continuously from selection through human submission feedback and cleanup. Sol is always the main attacker, never a coordinator-only process, and continues attacking while optional children start or fail. Preparation is an internal challenge-local preflight over only the selected identity, problem information, declared scope, source, prepared input, and service configuration. It may perform only the minimum challenge-local intake/triage needed to begin the decisive experiment. Whole-contest inventory, ranking, difficulty, and success estimates are not prerequisites or solve inputs. A sibling challenge change must not stale, rewrite, or block the selected challenge workspace.

Each solve generation is a run bound to exactly one `input_fingerprint` and append-only `target_revision`. A changed fingerprint or target revision creates a new run and changes only the active pointer. Earlier candidates, verified receipts, submission results, and history remain intact. Accepted/sealed evidence is immutable; only terminal convergence receipts may advance cleanup state. Every event, branch, candidate, resource allocation, insight packet, and control action is challenge- and run-local.

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
- Tier 0 is Sol-first; Tier 1 plans two children; Tier 2 three; Tier 3 four. Tier 4 replaces a stalled family without increasing configured width. Planned width is not running width. A child counts as running only after capacity admission, sandbox/input readiness, a native start receipt, and `RUNNING` status for the current run. Sol never waits for this lifecycle.
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

During work, Sol and children use the same compact typed receipts: `DECISIVE_EXPERIMENT`, `PRIMITIVE_CANDIDATE`, `PRIMITIVE_CONFIRMED`, `PRIMITIVE_REFUTED`, `WORKING_POC`, `REMOTE_ATTEMPT`, `FLAG_CANDIDATE`, `TYPED_BLOCKER`, `LONG_COMPUTE`, and `CHILD_TERMINAL_RESULT`. They record the observed result, exploit-proximity change, bounded output digest/excerpt, and relevant command/artifact references. A candidate is not confirmed progress: only a positive assertion plus an appropriate negative/control receipt can confirm it. General facts, generic artifacts, and narrative are not milestones. `REMOTE_FLAG_OBTAINED`, `SUBMISSION_RECOMMENDED`, and `ACCEPTED` are protected lifecycle events and cannot be published through the general event bus.

Sandbox execution records the compact command count automatically. A command run outside that managed path is followed immediately by a direct-argv `progress-command` receipt. This is command drift accounting, not full stdout capture; only the typed milestones above preserve bounded output evidence.

High-value events, plateaus, budget boundaries, and terminal results automatically run branch utility and append `RACE_TRANSITIONS.jsonl`. A confirmed primitive requires automatic race convergence: duplicate discovery stops or becomes PoC implementation, stalled lanes receive replacement packets, and Sol takeover to the minimal PoC/endgame is a required transition rather than narrative advice. Python records these packets and receipts; Sol alone performs native child lifecycle actions.

Command-only drift is bounded by configured per-category command/time thresholds. Only a confirmed primitive, working PoC, remote attempt, flag candidate, decisive refutation, typed blocker, or explicitly bounded long compute resets it. A fired gate creates one deduplicated control action for its evidence generation; Python emits the lifecycle packet and Sol applies or declines it.

Elastic scheduling is opt-in for proven long-compute workloads. `LONG_COMPUTE` requires a process identity, expected artifact, completion signal, maximum duration, checkpoint interval, resource requirement, cancel condition, and fallback plan bound to the run and session. Missing heartbeat/artifact change or duration expiry returns it to progress-gate review. Ordinary recon, probing, debugging, and PoC work stay at minimum allocation.

The dynamic scheduler allocates compute; it does not define solve progress. Short probes and quick PoCs run immediately without repeated `resource-status`, `resource-request`, `resource-plan`, or rebalance calls. Use scheduler planning before long symbolic execution, fuzzing, forensic scans, crypto/cracking, or AI computation, then inspect progress only at bounded slices. Scheduler management must never delay solver reasoning, a minimal PoC, remote execution, or flag display. New parallel harnesses use `CTF_OS_RECOMMENDED_WORKERS`.

## Scope, isolation, and flag fast path

- Attack exactly one selected challenge and only organizer-declared targets. Declared public/private/VPN/IPv6 and tcp, udp, http(s), tls, websocket/wss, dns, ssh, grpc, and custom endpoints are valid. Cloud metadata, Docker gateways, undeclared private LANs, other challenges, and unrelated hosts remain blocked.
- Challenge input/context are read-only. Each worker has private writable `/work`, `/evidence`, and `/artifacts`. Never mount the host Docker socket/root, SSH keys, browser profiles, personal cloud credentials/kubeconfig, or personal files.
- A child may mutate only its exact branch-private service. Shared challenge service lifecycle and global scheduler resize remain Sol-only.
- Challenge-provided temporary credentials and required mutations are allowed only inside the declared challenge account/project/tenant and are logged/redacted. Personal or ambient credentials are forbidden. Unsafe AI artifacts remain sandboxed and `trust_remote_code=True` is forbidden.
- `WORKING_POC` plus a declared remote starts configurable soft/hard transition deadlines. Before expiry record a `REMOTE_ATTEMPT`, verified remote receipt, or typed `TARGET_DOWN`, `AUTH_BLOCKED`, `RATE_LIMITED`, `ENDPOINT_CHANGED`, `PROTOCOL_MISMATCH`, or `LOCAL_ONLY_CHALLENGE` blocker. Assumptions about server failure do not satisfy the deadline.
- A current declared-remote observation, exact argv/digest, matching candidate, bounded output evidence, current target revision, and existing exploit artifact atomically yield a candidate, receipt, history update, result, and `SUBMISSION_RECOMMENDED`. The general event bus cannot manufacture this state. Print the exact flag immediately, stop low-value branches, and keep at most one optional verifier.
- Every candidate has a run-bound identity and provenance. Static format matching alone remains LOW/MEDIUM. HIGH exactness requires the original validator, two byte-identical independent extraction paths, remote acceptance, or explicit exact-byte proof; submission recommendation remains receipt-bound.
- Never submit to CTFd automatically. Human submission is the competition oracle. Record `WRONG` or `ACCEPTED` against the exact run and candidate. `WRONG` refutes only that candidate and resumes solving. `ACCEPTED` seals solved evidence, requests all active branches to stop, cleans CTF-OS-owned sandboxes/processes/resources idempotently, and remains `TERMINATION_PENDING` until Sol records native termination. Cleanup failure never erases the verified flag.
