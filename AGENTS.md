# CTF-OS — Sol-native routing contract

CTF-OS exists to obtain the first valid flag quickly in an authorized CTF. For every solve, `ctf_os/resources/agent-policy.md` is the authoritative competition and safety policy: this is a timed CTF solve, not vulnerability research; prefer the shortest executable exploit path and exploit first. `.codex/skills/ctf-solve/SKILL.md` defines the procedure, and `ctf_os/resources/knowledge/playbooks/<category>.md` defines the bounded category tactics. Do not duplicate or weaken those contracts here.

The current user-opened Sol session is lead attacker and owns native delegation, difficult exploit decisions, remote execution, and flag judgment. Python prepares inputs, records race/resource state, creates sandboxes, enforces scope, stores evidence/artifacts/receipts, and evaluates recommendations. Python never starts or supervises Codex/Claude, calls a model API, changes native child lifecycle, or submits a flag.

## Scope and minimum boundaries

- `incoming/<contest>/problems.txt` is the only user-maintained contest input; commands synchronize the internal `contest.md` deterministically.
- Attack exactly one selected challenge and only organizer-declared targets. Declared public/private/VPN/IPv6 and supported custom protocols are valid. Cloud metadata, Docker gateways, undeclared private LANs, unrelated hosts, and other challenges are not.
- Challenge input/context are read-only. Workers receive private writable `/work`, `/evidence`, and `/artifacts` only. Never access or mount the host Docker socket/root, SSH keys, browser profiles, personal cloud credentials/kubeconfig, or personal files.
- Challenge-provided temporary credentials and required cloud mutations are allowed only inside declared challenge scope, worker-private, logged, and redacted. Personal or ambient accounts are forbidden.
- Never submit a flag automatically. Surface the exact flag immediately for human submission; optional replay follows.

## Request routing

For “N번 문제 풀어라”, `category/name`, a challenge name, “이 문제 풀어라”, deep solve, or swarm request, keep the current user-opened Sol session and load `.codex/skills/ctf-solve/SKILL.md`. Resolve exactly one challenge, run its internal challenge-local preflight, and immediately begin direct file/runtime observation and exploit-first solving. Do not require whole-contest Intake, Triage, a Board, a new session, or repeated problem/remote input. Stop only for genuinely ambiguous selection; selected input or metadata that cannot be prepared safely; missing scope; an undeclared required target; required host credentials; or an out-of-scope action.

Whole-contest Intake and Triage are optional legacy/admin tools only. Invoke them only when the user explicitly requests whole-contest inventory or ranking. They are not Solve prerequisites, are not Solve readiness sources, and their artifacts must not be read, generated, changed, or invalidated by the Solve path. Current operations do not use a whole-contest priority Board or difficulty classification to guide a challenge solve.

For an explicit “intake 해라” or whole-contest inspection request, load `.codex/skills/ctf-intake/SKILL.md`. For an explicit “triage 해라” or whole-contest ranking request, load `.codex/skills/ctf-triage/SKILL.md`. Complete only that requested administrative action and do not present it as the normal route into Solve.

## Solve invariants

- Use the policy's exploit-first loop: minimal observation, at most three concrete exploit hypotheses, cheapest decisive experiment, kill/promote, smallest working PoC, declared remote as soon as plausible, immediate flag display.
- Category branch templates are fallback only. Evidence determines the actual exploit mechanisms. `independent-full-solve` races independently for the shortest flag path and never means comprehensive analysis.
- `race-plan-start` records `PLANNED` prompt packets but never creates children. Sol admits capacity, creates and verifies each branch-private sandbox/input view, then owns native delegation and its start receipt while continuing its own minimal-exploit lane.
- Facts and artifacts are progress only when they increase exploit proximity. Research drift, repeated blockers, or information without proximity gain triggers takeover or a genuinely different attack family.
- Publish a primitive, working PoC, flag candidate, or remote flag before general summaries. Sol checks management state only at branch creation, explicit blocker, primitive, working artifact, plateau, flag candidate, or child termination.
- Short probes and quick PoCs outrank scheduler administration. Use resource planning before long symbolic/fuzz/forensic/crypto/AI computation only. Python recommends allocations; Sol keeps attacking and alone changes native lifecycle.
- The shared challenge service and global resource resize are Sol-only. A worker may mutate only its own exact branch-private service. Sandbox isolation remains mandatory.
- A declared-remote observation, exact command receipt, pattern-matching candidate, current target revision, and exploit artifact atomically produce the verified receipt and `SUBMISSION_RECOMMENDED`. Clean replay is optional and never delays human submission. Human `WRONG` or `ACCEPTED` feedback is recorded against the exact run and candidate; acceptance begins terminal convergence without Python taking ownership of native session termination.
