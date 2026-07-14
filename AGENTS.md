# CTF-OS — Sol-native routing contract

CTF-OS exists to obtain the first valid flag quickly in an authorized CTF. For every solve, `ctf_os/resources/agent-policy.md` is the authoritative competition and safety policy: this is a timed CTF solve, not vulnerability research; prefer the shortest executable exploit path and exploit first. `.codex/skills/ctf-solve/SKILL.md` defines the procedure, and `ctf_os/resources/knowledge/playbooks/<category>.md` defines the bounded category tactics. Do not duplicate or weaken those contracts here.

The current user-opened Sol session is lead attacker and owns native delegation, difficult exploit decisions, remote execution, and flag judgment. Python prepares inputs, records race/resource state, creates sandboxes, enforces scope, stores evidence/artifacts/receipts, and evaluates recommendations. Python never starts or supervises Codex/Claude, calls a model API, changes native child lifecycle, or submits a flag.

## Scope and minimum boundaries

- `incoming/<contest>/problems.txt` is the only user-maintained contest input; Intake generates internal `contest.md`.
- Attack exactly one selected challenge and only organizer-declared targets. Declared public/private/VPN/IPv6 and supported custom protocols are valid. Cloud metadata, Docker gateways, undeclared private LANs, unrelated hosts, and other challenges are not.
- Challenge input/context are read-only. Workers receive private writable `/work`, `/evidence`, and `/artifacts` only. Never access or mount the host Docker socket/root, SSH keys, browser profiles, personal cloud credentials/kubeconfig, or personal files.
- Challenge-provided temporary credentials and required cloud mutations are allowed only inside declared challenge scope, worker-private, logged, and redacted. Personal or ambient accounts are forbidden.
- Never submit a flag automatically. Surface the exact flag immediately for human submission; optional replay follows.

## Request routing

For “intake 해라”, “대회 문제 읽어라”, “문제 목록 준비해라”, or a named contest intake request, load `.codex/skills/ctf-intake/SKILL.md`. Intake is a dedicated no-solve session: inspect all challenges, generate `output/<contest>/intake.json` and `INTAKE.md`, print the numbered status list, and stop.

For “triage 해라”, “추천 풀이 순서 정해라”, “문제 우선순위 정해라”, or a named triage request after Intake, load `.codex/skills/ctf-triage/SKILL.md`. Triage is a dedicated no-solve session using only Intake metadata. Run `triage-prepare`, decide the order, run `triage-finalize`, show the READY/BLOCKED Board, and stop.

For “N번 문제 풀어라”, `category/name`, a challenge name, deep solve, or swarm request, open a new session and load `.codex/skills/ctf-solve/SKILL.md`. Solve exactly one challenge after current finalized triage. Stop only for ambiguous selection/contest, missing scope, an undeclared external target, required host credentials, or an out-of-scope action.

## Solve invariants

- Use the policy's exploit-first loop: minimal observation, at most three concrete exploit hypotheses, cheapest decisive experiment, kill/promote, smallest working PoC, declared remote as soon as plausible, immediate flag display.
- Category branch templates are fallback only. Evidence determines the actual exploit mechanisms. `independent-full-solve` races independently for the shortest flag path and never means comprehensive analysis.
- `race-plan-start` records prompt packets but never creates children. Sol immediately creates admitted children through native delegation, creates each sandbox, and continues its own minimal-exploit lane.
- Facts and artifacts are progress only when they increase exploit proximity. Research drift, repeated blockers, or information without proximity gain triggers takeover or a genuinely different attack family.
- Publish a primitive, working PoC, flag candidate, or remote flag before general summaries. Sol checks management state only at branch creation, explicit blocker, primitive, working artifact, plateau, flag candidate, or child termination.
- Short probes and quick PoCs outrank scheduler administration. Use resource planning before long symbolic/fuzz/forensic/crypto/AI computation only. Python recommends allocations; Sol keeps attacking and alone changes native lifecycle.
- The shared challenge service and global resource resize are Sol-only. A worker may mutate only its own exact branch-private service. Sandbox isolation remains mandatory.
- A declared-remote observation, exact command receipt, pattern-matching candidate, and exploit artifact produce `SUBMISSION_RECOMMENDED`. Clean replay is optional and never delays human submission.
