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

Each challenge snapshot has a deterministic `challenge_instance_id` bound to challenge ID, prepared input and metadata digests, append-only target revision, flag metadata, optional target image digest, and transformation seed. Each independent execution has a fresh `attempt_id`; its `run_id` binds both identities. Compatibility preparation resumes the current attempt, while an explicit fresh attempt never inherits ledgers, candidates, model context, worker state, artifacts, evidence, sandbox/container identity, ports, caches, or generated solver files. Earlier attempts remain queryable and accepted/sealed evidence is immutable. Every event, branch, candidate, resource allocation, insight packet, and control action is attempt- and run-local.

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
- Solve mode, not tier, is the authoritative runtime treatment. Live competition defaults to `adaptive-race`: Sol starts immediately, child active width starts at zero, and 60–90 seconds of bounded observation precedes any evidence-selected 0–3 distinct child mechanisms. One replacement is allowed only after plateau/refutation evidence; a start failure may degrade live competition to Sol-only while remaining recorded.
- `sol-only` never plans or starts a child. `fixed-race` uses exactly three frozen category-template intents, forbids evidence-driven width changes and replacement, and has maximum model concurrency four including Sol. A fixed-race branch start failure is an environment failure/invalid matched block, never a quiet Sol-only treatment.
- Tier remains only legacy compatibility/resource-envelope/maximum-width metadata. Tier 0 maps to `sol-only`; Tier 1–4 map to `adaptive-race`. Tier never proves or causes native child creation, running width, solve mode, benchmark arm, model, or reasoning. Conflicting explicit mode/tier input is rejected.
- Category templates are fallback lanes in adaptive mode and the preregistered frozen treatment in fixed-race; otherwise challenge evidence chooses mechanisms.
- `independent-full-solve` means: independently race for the shortest valid flag path; do not produce a comprehensive analysis, wait for siblings, or collect evidence beyond what the exploit needs.
- `RACE_LINEAGE.jsonl` is the append-only authoritative branch lifecycle. Initial and replacement branches both traverse `PLANNED → CAPACITY_ADMITTED → SANDBOX_READY → AWAITING_NATIVE_START → NATIVE_STARTED → RUNNING`. Only the latest `RUNNING` branches count as active width; planned width is always reported separately. `DELEGATION_PLAN.json` and `STATE.branches` are lineage projections.
- A started branch cannot be superseded or made stale without exact stop or child-terminal evidence followed by sandbox cleanup and resource release. Whole-plan restart refuses to publish a new authoritative generation while a started prior branch lacks acknowledgement. An unstarted branch closes only with an explicit not-started terminal receipt. Python validates lineage and receipts; Sol alone performs native start/stop.
- Admission overlap is advisory at 0.95. Repeated session IDs and materially exact duplicates are denied; parallel/independent solves, alternate implementations, verification, and plateau escape remain exceptions. Requested model/reasoning become an executable routing request only through a doctor-validated native custom-agent profile; they are never proof of the observed runtime identity.

### Evidence-driven branch model routing

The lead remains the strongest Sol-capable model at `xhigh`; Max is never the whole-session default. A branch contract selects one profile from its hypothesis, mechanism, decisive experiment, expected artifact, current evidence, typed blocker, and exploit proximity—not its role label, solve mode, tier, Board, difficulty estimate, or category alone.

- `MECHANICAL`: Luna-equivalent at medium or high for exact extraction, filtering, batching, normalization, deduplication, and fixed command repetition. It cannot independently solve or derive a mechanism.
- `BOUNDED_EXPERIMENT`: Terra-equivalent at high for one already concrete hypothesis, sink, oracle, or positive/negative control.
- `IMPLEMENTATION`: Terra-equivalent at high for a payload, solver, minimal PoC, local/remote adaptation, or completion of a confirmed artifact. New mechanisms and difficult heap/ROP/crypto/reversing/AI exploit design stay on Sol.
- `DEEP_SOLVER`: Sol-equivalent at xhigh for `independent-full-solve`, a distinct attack family, a new difficult mechanism, or a complex exploit chain.
- `CONFIRMED_BOTTLENECK`: one Sol-equivalent Max lane only after `PRIMITIVE_CONFIRMED`, a specific typed reasoning blocker, no working PoC/flag path, and at least one observed xhigh decisive experiment. Docker/dependency/tool failures, target failure, rate limits, long compute, broad recon, generic research, and repeated commands never qualify.

The current installed mappings are project custom agents `ctf_mechanical → gpt-5.6-luna/medium`, `ctf_mechanical_high → gpt-5.6-luna/high`, `ctf_terra_high → gpt-5.6-terra/high`, `ctf_deep_solver → gpt-5.6-sol/xhigh`, and `ctf_max_endgame → gpt-5.6-sol/max`. These runtime identifiers are not assumed portable: bounded doctor preflight revalidates each file against the installed Codex catalog and native delegation support. The branch packet names the exact custom agent and embeds the routing contract and limits. Sol makes the native delegation call asynchronously and continues attacking; Python and shell never start a model. If the selection surface or requested capability is unavailable, record `ROUTING_UNSUPPORTED` and continue live solving with an explicitly recorded allowed fallback, inherited child, or Sol-only lane.

The version-2 native start receipt binds operation ID, run, challenge, target revision, parent/child session, routing profile, requested class/model/reasoning, and only runtime-evidenced observed model/reasoning. `OBSERVED`, `NOT_OBSERVABLE`, `UNSUPPORTED`, and `CONFLICT` are explicit states. Requested values are never copied into observed fields. Exact matches classify as `ROUTING_MATCHED`; declared profile fallbacks as `FALLBACK_MATCHED`; other differences as `ROUTING_MISMATCH`; unavailable evidence/capability as `RUNTIME_NOT_OBSERVABLE` or `ROUTING_UNSUPPORTED`. Reusing an operation ID with another identity or importing a receipt from another run/session is a conflict.

Branch utility and the separate model-routing benchmark diagnostic attribute performance only to observed runtime identity. A successful requested Terra lane observed as Sol is not Terra performance; an unobserved or mismatched failure is not failure evidence for the requested profile. Existing A/B/C/D solve-mode treatments and decisions remain unchanged. Live solving never pauses merely because routing is unsupported or unobservable.

A Max lease is at most 600 seconds or two decisive experiments and stops on `WORKING_POC`, `REMOTE_ATTEMPT`, `FLAG_CANDIDATE`, `PRIMITIVE_REFUTED`, expiry, or the second experiment. A primitive immediately triggers Sol takeover; a working implementation immediately transitions to remote; a Max artifact is handed to Sol rather than allowing broad follow-on work. At most one Max lane and the existing whole-race model concurrency cap apply. Observable Ultra cannot be nested with `adaptive-race` or `fixed-race`; an unobservable Ultra state is recorded as `NOT_OBSERVABLE`, never assumed safe or enabled.

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

During work, Sol and children use the same compact typed receipts: `DECISIVE_EXPERIMENT`, `PRIMITIVE_CANDIDATE`, `PRIMITIVE_CONFIRMED`, `PRIMITIVE_REFUTED`, `WORKING_POC`, `REMOTE_ATTEMPT`, `FLAG_CANDIDATE`, `TYPED_BLOCKER`, `LONG_COMPUTE`, and `CHILD_TERMINAL_RESULT`. They record the observed result, exploit-proximity change, bounded output digest/excerpt, and relevant command/artifact references. Receipt identity excludes sequence and time; a stable operation ID permits safe retry and conflicts if its canonical evidence changes. Milestone receipts and race lineage are authoritative, while progress, timing, candidate, run state, delegation-plan, race/control/scheduler, and compatibility files are restartable projections. A candidate is not confirmed progress: only a positive assertion plus an appropriate negative/control receipt can confirm it. General facts, generic artifacts, and narrative are not milestones. `REMOTE_FLAG_OBTAINED`, `SUBMISSION_RECOMMENDED`, and `ACCEPTED` are protected lifecycle events and cannot be published through the general event bus.

Sandbox execution records the compact command count automatically. A command run outside that managed path is followed immediately by a direct-argv `progress-command` receipt. This is command drift accounting, not full stdout capture; only the typed milestones above preserve bounded output evidence.

High-value events, plateaus, budget boundaries, and terminal results automatically run branch utility and append `RACE_TRANSITIONS.jsonl`. A confirmed primitive requires automatic race convergence: duplicate discovery stops or becomes PoC implementation, an adaptive stalled lane may receive the single evidence-backed replacement packet, and Sol takeover to the minimal PoC/endgame is a required transition rather than narrative advice. Fixed-race never replaces a lane. Python records these packets and receipts; Sol alone performs native child lifecycle actions.

Command-only drift is bounded by configured per-category command/time thresholds. Only a confirmed primitive, working PoC, remote attempt, flag candidate, decisive refutation, typed blocker, or explicitly bounded long compute resets it. A fired gate creates one deduplicated control action for its evidence generation; Python emits the lifecycle packet and Sol applies it only with the action-specific authoritative receipt, or declines/supersedes/expires it.

Elastic scheduling is opt-in for proven long-compute workloads. `LONG_COMPUTE` requires sandbox/container/process identity, exact argv, expected artifact, completion signal, maximum duration, checkpoint interval, resource requirement, cancel condition, and fallback plan bound to the run and session. Python directly verifies process argv and branch-local artifact change; caller booleans, utilization, and generic artifact counts cannot authorize scale-up. Missing heartbeat/artifact change or duration expiry returns it to progress-gate review. Ordinary recon, probing, debugging, and PoC work stay at minimum allocation.

The dynamic scheduler allocates compute; it does not define solve progress. Short probes and quick PoCs run immediately without repeated `resource-status`, `resource-request`, `resource-plan`, or rebalance calls. Use scheduler planning before long symbolic execution, fuzzing, forensic scans, crypto/cracking, or AI computation, then inspect progress only at bounded slices. Scheduler management must never delay solver reasoning, a minimal PoC, remote execution, or flag display. New parallel harnesses use `CTF_OS_RECOMMENDED_WORKERS`.

### Manual external rescue profile

A manual Claude rescue is an exact-run external solver session, not a race child, benchmark treatment, or transfer of Solve ownership. It is available only on mutable LIVE competition runs. Python may validate the current run, create an immutable bounded packet, prepare a rescue-only sandbox/workspace, validate a returned JSON document, and clean that exact rescue container. Python, Codex, and shell automation never launch, supervise, restart, route, or infer the model process. The human explicitly starts and stops Claude in another terminal, while the current user-opened Sol session retains the solve.

Rescue state is append-only and run-local under `runs/<run-id>/rescue/`. Its ledger and immutable packet are authoritative; `RESCUE_STATE.json` and `CODEX-RESUME.md` are projections or handoff views. A rescue is absent from race lineage, delegation plans, branch projections, and native child widths. Its bind workspace exposes only rescue-local `work`, `evidence`, and `artifacts` as writable, selected generated context and prepared challenge input as read-only, and only organizer-declared targets through the existing sandbox network policy. A managed service is attach-only and remains owned by `sol-main`.

Claude output remains candidate insight. Return validation never modifies Solve state, candidates, milestone receipts, race events, verified flag receipts, or submission recommendations. A claimed remote flag may reach `SUBMISSION_RECOMMENDED` only after Sol independently satisfies the existing protected remote receipt contract. Submission remains human-only.

## Scope, isolation, and flag fast path

- Attack exactly one selected challenge and only organizer-declared targets. Declared public/private/VPN/IPv6 and tcp, udp, http(s), tls, websocket/wss, dns, ssh, grpc, and custom endpoints are valid. Cloud metadata, Docker gateways, undeclared private LANs, other challenges, and unrelated hosts remain blocked.
- Challenge input/context are read-only. Each worker has private writable `/work`, `/evidence`, and `/artifacts`. Never mount the host Docker socket/root, SSH keys, browser profiles, personal cloud credentials/kubeconfig, or personal files.
- A child may mutate only its exact branch-private service. Shared challenge service lifecycle and global scheduler resize remain Sol-only.
- Challenge-provided temporary credentials and required mutations are allowed only inside the declared challenge account/project/tenant and are logged/redacted. Personal or ambient credentials are forbidden. Unsafe AI artifacts remain sandboxed and `trust_remote_code=True` is forbidden.
- `WORKING_POC` plus a declared remote starts configurable soft/hard transition deadlines. Before expiry record a `REMOTE_ATTEMPT`, verified remote receipt, or typed `TARGET_DOWN`, `AUTH_BLOCKED`, `RATE_LIMITED`, `ENDPOINT_CHANGED`, `PROTOCOL_MISMATCH`, or `LOCAL_ONLY_CHALLENGE` blocker. Assumptions about server failure do not satisfy the deadline.
- A current declared-remote observation, exact argv/digest, matching candidate, bounded output evidence, current target revision, and existing exploit artifact atomically yield a candidate, receipt, history update, result, and `SUBMISSION_RECOMMENDED`. The general event bus cannot manufacture this state. Print the exact flag immediately, stop low-value branches, and keep at most one optional verifier.
- Every candidate has a run-bound identity and provenance. Static format matching alone remains LOW/MEDIUM. HIGH exactness requires the original validator, two byte-identical independent extraction paths, remote acceptance, or explicit exact-byte proof; submission recommendation remains receipt-bound.
- Never submit to CTFd automatically. Human submission is the competition oracle. Record `WRONG` or `ACCEPTED` against the exact run and candidate. `WRONG` refutes only that candidate and resumes solving. `ACCEPTED` seals solved evidence, requests all active branches to stop, cleans CTF-OS-owned sandboxes/processes/resources idempotently, and remains `TERMINATION_PENDING` until Sol records native termination. Cleanup failure never erases the verified flag.
