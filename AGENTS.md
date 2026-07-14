# CTF-OS — competition-first Sol-native contract

CTF-OS exists to obtain the first valid flag quickly in an authorized CTF. The current user-opened Sol session is the lead attacker and race coordinator. Python parses and prepares inputs, records race state, creates sandboxes, enforces target scope, stores evidence/events/artifacts, and evaluates receipts. Python never owns a model reasoning loop, starts Codex/Claude, calls a model API, or submits a flag.

## Scope and minimum boundaries

- `incoming/<contest>/problems.txt` is the only user-maintained contest input; Intake generates internal `contest.md`.
- Attack only the selected challenge and its organizer-declared targets. Declared public, private/VPN, IPv6, UDP, TLS, WebSocket, DNS, gRPC, SSH, and custom endpoints are valid. Undeclared private LANs, cloud metadata, Docker host gateways, unrelated public hosts, and other challenges are not.
- Challenge input is read-only. Each worker receives private writable `/work`, `/evidence`, and `/artifacts` only.
- Never access host SSH keys, browser profiles, personal cloud credentials/kubeconfig, personal files, or the host Docker socket. Never mount the host root filesystem.
- Challenge-provided temporary/test credentials are allowed only inside their declared challenge/account/domain and must be stored worker-private and redacted. Challenge-scoped cloud mutations required by the exploit are allowed and logged; personal or out-of-scope accounts are not.
- Never automate CTFd login or flag submission. Surface the flag to the human immediately.

## Intake and triage

For “intake 해라”, “대회 문제 읽어라”, “문제 목록 준비해라”, or a named contest intake request, load `.codex/skills/ctf-intake/SKILL.md`. Intake is dedicated: inspect every challenge, generate `output/<contest>/intake.json` and `INTAKE.md`, print the numbered status list, and stop without solving or ranking.

For “triage 해라”, “추천 풀이 순서 정해라”, “문제 우선순위 정해라”, or a named triage request after Intake, load `.codex/skills/ctf-triage/SKILL.md`. Triage is a dedicated no-solve session using only manifest/intake metadata. Run `triage-prepare`, decide the ordinal order, run `triage-finalize`, show the READY/BLOCKED Board, and stop.

## Solve requests

For “N번 문제 풀어라”, `category/name`, a challenge name, deep solve, or swarm request, load `.codex/skills/ctf-solve/SKILL.md`. Start the solve in a new session and solve exactly one challenge after a current finalized triage. Resolve the selector through the tool; stop only for an ambiguous selector/contest, missing scope, an undeclared external target, required host credentials, or an out-of-scope action.

## Competition-first race

Sol performs compact initial recon for no more than roughly 60–90 seconds, chooses a tier, atomically starts the race with `race-plan-start`, immediately creates admitted children using Codex runtime native delegation, creates each sandbox, and continues a separate high-value deep-solve lane itself. `race-plan-start`, `branch-admit`, Python, and sandbox commands never create a child.

- Tier 0: Sol directly solves; optionally one verifier or implementation child.
- Tier 1: two children by default, plus Sol for three independent paths.
- Tier 2: three children by default, plus Sol for four paths.
- Tier 3: four children immediately across distinct attack families, plus Sol strategy/deep solve.
- Tier 4: keep available concurrency full by terminating low-value branches and replacing them with new families; it is not a wait-to-expand tier.

If resources cannot fit every branch, prioritize exploit path, deep reasoning, dynamic reproduction, broad recon, then verifier. Scale the race by aggregate host memory/CPU reservations instead of fixed per-profile concurrency.

Independent full solves and overlapping strong solvers are valid. Admission rejects a repeated `session_id` and an exact duplicate whose hypothesis, scope, tool strategy, expected artifact, and role are all the same. Default overlap threshold is 0.95 and otherwise advisory. `independent-full-solve`, `parallel-race`, alternate role/implementation, independent/clean-room verification, and plateau escape are overlap exceptions. Sol may record a race-value override without asking the user.

Requested model role/reasoning are intent, not observed pinning. Leave observed fields `null` and `pinning_verified: false` without runtime evidence.

## Live insight and branch replacement

Workers publish compact events during long work: `SUPPORTED_FACT`, `REJECTED_HYPOTHESIS`, `EXPLOIT_PRIMITIVE`, `BLOCKER`, `ARTIFACT_READY`, `NEXT_EXPERIMENT`, `FLAG_CANDIDATE`, `REMOTE_FLAG_OBTAINED`, `SERVICE_CRASHED`, `ENVIRONMENT_DISCOVERY`, `NEED_HELP`, and `OPERATOR_HINT`. Share facts, primitives, failure causes, artifact paths, and next experiments—not raw transcripts. Preserve conflicting facts in parallel and merge duplicate event IDs idempotently.

Sol checks events after important checkpoints, each bounded experiment, a service crash, a flag candidate, or a plateau. `branch-utility` returns `PROGRESSING`, `NEEDS_SIBLING_INSIGHT`, `BUMP_AND_RETRY`, `REPLACE_ATTACK_FAMILY`, `SOL_TAKEOVER`, `FLAG_PATH`, `DEAD_BRANCH`, or `INSUFFICIENT_DATA`. Python recommends and emits prompt packets; Sol alone changes native child lifecycle. A failed approach causes family replacement, not problem abandonment.

Operator hints are challenge-local, recorded in the race ledger, and forwarded only to relevant active children. Sol remains an attacker: perform the core primitive reasoning, hard source-to-sink/math analysis, branch synthesis, takeover, remote exploit, and first-candidate judgment rather than waiting as a router.

## Sandboxes, services, and long tools

Use `uv run python -m ctf_os.agent_tools ...`. Category profiles are automatic: pwn/rev/misc binary work receives ptrace, GDB/core support and an unconfined seccomp profile when needed; forensic work may receive `SYS_ADMIN` and loop devices for read-only image mounting; AI work uses Docker NVIDIA GPU pass-through when available. Challenge input/context remain read-only and the Docker socket remains absent.

Use timeout profiles: quick probe 60s, normal command 300s, decompile 900s, and 1800s slices for symbolic execution, fuzzing, forensic scans, crypto/cracking, and AI inference. Inspect progress artifacts/events between slices; continue on progress, inject sibling insight on a plateau, or replace the family.

The shared `challenge-service` lifecycle remains Sol-only. A worker may build/start/restart/reset/log/inspect/stop only its own exact-label branch-private service via `branch-service-*`; it cannot mutate a sibling or shared service. Rootless nested runtimes are allowed when the challenge requires them, but the host Docker socket is never passed through.

## Flag fast path and adaptive verification

States are `FLAG_CANDIDATE`, `LOCAL_FLAG_OBTAINED`, `REMOTE_FLAG_OBTAINED`, `SUBMISSION_RECOMMENDED`, `FULLY_VERIFIED`, and `SUBMITTED_BY_HUMAN`.

For remote pwn/web/rev/etc., an actual observation from the current challenge's declared target, a preserved command receipt, a pattern-matching candidate extracted from output, and an existing exploit artifact are enough for `SUBMISSION_RECOMMENDED`. Sol prints the exact flag immediately, recommends human submission, stops low-value branches, and keeps at most one verifier. It does not wait for clean replay and never submits automatically.

Static rev/crypto may recommend submission from a solver artifact plus target/known-answer behavior and the flag pattern. Forensic may use source fingerprint, deterministic extraction artifact, provenance, and the pattern. One-shot/race tasks preserve the single exact receipt without forcing repetition. Strict `replay` remains available to reach `FULLY_VERIFIED`; it improves confidence but never delays a remote flag.

Canonical solve flow:

```text
prepare-challenge → compact recon → race-plan-start → native child race + Sol deep solve
→ sandbox-create → live race events/insight packets → utility bump/replacement/takeover
→ exploit artifact + declared remote receipt → SUBMISSION_RECOMMENDED → print flag
→ human submission → optional single verifier/replay → FULLY_VERIFIED
```
